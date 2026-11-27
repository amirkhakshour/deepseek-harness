import { describe, expect, it } from 'vitest'
import { assertPublicDestination, isMetadataAddress, isPublicAddress } from '../src/destination.ts'

describe('destination policy', () => {
  it('classifies public and non-public IPv4 literals', () => {
    for (const address of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) {
      expect(isPublicAddress(address), address).toBe(true)
    }
    for (const address of [
      '0.0.0.0', '10.1.2.3', '127.0.0.1', '169.254.1.1', '172.16.0.1', '172.31.255.255',
      '192.168.1.1', '100.64.0.1', '192.0.0.1', '198.18.0.1', '198.51.100.7', '203.0.113.9',
      '224.0.0.1', '255.255.255.255',
    ]) {
      expect(isPublicAddress(address), address).toBe(false)
    }
  })

  it('classifies IPv6 literals, including IPv4-mapped forms', () => {
    expect(isPublicAddress('2606:4700:4700::1111')).toBe(true)
    for (const address of ['::', '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1']) {
      expect(isPublicAddress(address), address).toBe(false)
    }
  })

  it('names the cloud metadata endpoints', () => {
    expect(isMetadataAddress('169.254.169.254')).toBe(true)
    expect(isMetadataAddress('100.100.100.200')).toBe(true)
    expect(isMetadataAddress('fd00:ec2::254')).toBe(true)
    expect(isMetadataAddress('169.254.1.1')).toBe(false)
  })

  it('refuses the metadata endpoint even when private destinations are allowed', async () => {
    await expect(assertPublicDestination(new URL('http://169.254.169.254/latest/meta-data/'), { allowPrivate: true }))
      .rejects.toMatchObject({ code: 'WEB_BLOCKED_URL' })
  })

  it('follows the allowPrivate policy for loopback and private literals', async () => {
    await expect(assertPublicDestination(new URL('http://127.0.0.1:8080/'), { allowPrivate: true })).resolves.toBeUndefined()
    await expect(assertPublicDestination(new URL('http://127.0.0.1:8080/'), { allowPrivate: false }))
      .rejects.toMatchObject({ code: 'WEB_BLOCKED_URL' })
    await expect(assertPublicDestination(new URL('http://10.0.0.7/admin'), { allowPrivate: false }))
      .rejects.toMatchObject({ code: 'WEB_BLOCKED_URL' })
  })

  it('resolves hostnames before deciding', async () => {
    await expect(assertPublicDestination(new URL('http://localhost/'), { allowPrivate: false }))
      .rejects.toMatchObject({ code: 'WEB_BLOCKED_URL' })
    await expect(assertPublicDestination(new URL('http://[::1]/'), { allowPrivate: false }))
      .rejects.toMatchObject({ code: 'WEB_BLOCKED_URL' })
  })
})
