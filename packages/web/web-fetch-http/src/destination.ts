/**
 * Destination policy for the HTTP(S) fetch provider — the half that decides
 * whether a request may leave the machine at all. The provider's composition
 * documents this control ("accepts only public HTTP(S) destinations, resolves
 * and validates every destination"), so it is enforced here, before every
 * transport attempt, rather than being implied by the proxy configuration.
 *
 * Two independent rules:
 *
 * - The cloud metadata endpoints are refused unconditionally. No supported use
 *   of this provider needs instance credentials, and a page the Agent reads can
 *   otherwise drive `web_fetch` at `169.254.169.254` with no approval prompt.
 * - Every other non-public destination (loopback, private, link-local,
 *   unique-local) is refused unless the deployment opts in with
 *   `allowPrivateDestinations`, because reaching intranet URLs is a documented
 *   capability of this provider.
 *
 * @module @deepseek-ai/dsh-web-fetch-http/destination
 */

import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { WebError } from '@deepseek-ai/dsh-web'

/** Whether a destination policy admits non-public addresses (intranet opt-in). */
export interface DestinationPolicy {
  /** When true, loopback, private and link-local addresses are permitted (metadata never is). */
  readonly allowPrivate: boolean
}

/** Link-local metadata addresses used by cloud instance credential services. */
const METADATA_ADDRESSES = new Set([
  '169.254.169.254', // AWS, GCP, Azure, OpenStack
  '169.254.170.2', // ECS task metadata
  '100.100.100.200', // Alibaba Cloud
  'fd00:ec2::254', // AWS IPv6 metadata
])

/**
 * Whether an address is a cloud instance metadata endpoint.
 *
 * @param address - an IPv4 or IPv6 literal (no brackets).
 * @returns true when the address belongs to a metadata service.
 */
export function isMetadataAddress(address: string): boolean {
  return METADATA_ADDRESSES.has(address.toLowerCase())
}

/**
 * Classify one literal IP address.
 *
 * Rejected: unspecified, loopback, link-local, RFC1918, carrier-grade NAT,
 * unique-local IPv6, multicast, documentation/benchmark ranges, and
 * IPv4-mapped IPv6 whose embedded address is itself non-public.
 *
 * @param address - an IPv4 or IPv6 literal (no brackets).
 * @returns true when the address is a public destination.
 */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address)
  if (family === 4) return isPublicIpv4(address)
  if (family === 6) return isPublicIpv6(address)
  // Anything that is not an IP literal is not a destination this check can vouch for.
  return false
}

/** Whether an IPv4 literal lies outside every non-public range. */
function isPublicIpv4(address: string): boolean {
  const octets = address.split('.').map(part => Number(part))
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false
  const [a = 0, b = 0] = octets
  if (a === 0) return false // 0.0.0.0/8 "this network"
  if (a === 10) return false // RFC1918
  if (a === 127) return false // loopback
  if (a === 169 && b === 254) return false // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false // RFC1918
  if (a === 192 && b === 168) return false // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return false // carrier-grade NAT
  if (a === 192 && b === 0) return false // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return false // benchmarking
  if (a === 198 && b === 51) return false // documentation
  if (a === 203 && b === 0) return false // documentation
  if (a >= 224) return false // multicast, reserved, broadcast
  return true
}

/** Whether an IPv6 literal (including IPv4-mapped forms) is a public destination. */
function isPublicIpv6(address: string): boolean {
  const lower = address.toLowerCase()
  const zoneIndex = lower.indexOf('%')
  const bare = zoneIndex === -1 ? lower : lower.slice(0, zoneIndex)
  if (bare === '::' || bare === '::1') return false // unspecified, loopback
  // IPv4-mapped (::ffff:1.2.3.4) and IPv4-compatible literals: judge the embedded address.
  const embedded = /^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/.exec(bare)
  if (embedded?.[1] !== undefined) return isPublicIpv4(embedded[1])
  const firstGroup = parseInt(bare.split(':')[0] ?? '', 16)
  if (Number.isNaN(firstGroup)) return false
  if ((firstGroup & 0xfe00) === 0xfc00) return false // unique-local fc00::/7
  if ((firstGroup & 0xffc0) === 0xfe80) return false // link-local fe80::/10
  if ((firstGroup & 0xff00) === 0xff00) return false // multicast ff00::/8
  return true
}

/**
 * Enforce the destination policy for one URL, resolving hostnames first.
 *
 * A hostname is rejected if **any** address it resolves to is forbidden: a
 * resolver that returns one routable and one private answer must not be able
 * to reach the private one through a retry or a rotation.
 *
 * @param url - the parsed request URL.
 * @param policy - whether non-public destinations are permitted.
 * @param signal - caller lifetime; aborts the resolution.
 * @throws WebError `WEB_BLOCKED_URL` when the destination is not permitted.
 */
export async function assertPublicDestination(
  url: URL,
  policy: DestinationPolicy,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted()
  const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname
  const addresses = await resolveDestination(hostname)
  signal?.throwIfAborted()
  const metadata = addresses.find(isMetadataAddress)
  if (metadata !== undefined) throw refusal(hostname, metadata, 'a cloud metadata endpoint')
  if (policy.allowPrivate) return
  const nonPublic = addresses.find(address => !isPublicAddress(address))
  if (nonPublic !== undefined) throw refusal(hostname, nonPublic, 'not a public address')
}

/** Every address a destination names, refusing one that cannot be resolved. */
async function resolveDestination(hostname: string): Promise<string[]> {
  if (isIP(hostname) !== 0) return [hostname]
  let answers: { address: string }[]
  try {
    answers = await lookup(hostname, { all: true, verbatim: true })
  } catch (error: unknown) {
    throw new WebError(`could not resolve destination "${hostname}"`, 'WEB_BLOCKED_URL', { cause: error })
  }
  if (answers.length === 0) throw new WebError(`could not resolve destination "${hostname}"`, 'WEB_BLOCKED_URL')
  return answers.map(answer => answer.address)
}

/** One refusal message, naming only what the caller already supplied. */
function refusal(hostname: string, address: string, why: string): WebError {
  return new WebError(
    `destination "${hostname}" (resolved to ${address}) is ${why}`,
    'WEB_BLOCKED_URL',
  )
}
