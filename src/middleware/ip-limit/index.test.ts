import { Hono } from '../..'
import type { GetConnInfo } from '../../helper/conninfo'
import { HTTPException } from '../../http-exception'
import { ipLimit, isMatchForRule } from '.'

describe('ipLimit middleware', () => {
  it('Should limit', async () => {
    const getConnInfo: GetConnInfo = (c) => {
      return {
        remote: {
          address: c.env.ip,
        },
      }
    }
    const app = new Hono<{
      Bindings: {
        ip: string
      }
    }>()
    app.use(
      '/rules',
      ipLimit(getConnInfo, {
        allow: ['192.168.1.0', '192.168.2.0/24'],
        deny: ['192.168.2.10'],
      })
    )
    app.get('/rules', (c) => c.text('Hello World!'))

    app.use(
      '/only-deny',
      ipLimit(getConnInfo, {
        deny: ['192.168.2.10'],
      })
    )
    app.get('/only-deny', (c) => c.text('Hello World!'))

    app.use(
      '/handlers',
      ipLimit(getConnInfo, {
        allow: ['192.168.1.0', '192.168.2.0/24'],
        deny: ['192.168.2.10'],
        denyHandler: () =>
          new HTTPException(403, {
            res: new Response('Denied', {
              status: 403,
            }),
          }),
        validHandler: ({ remote, allow, deny }) => {
          if (remote.address === '192.168.3.15') {
            return allow
          } else if (remote.address === '192.168.3.20') {
            return deny
          }
        },
      })
    )

    app.get('/handlers', (c) => c.text('Hello World!'))

    // /rules
    expect((await app.request('/rules', {}, { ip: '0.0.0.0' })).status).toBe(403)
    expect(await (await app.request('/rules', {}, { ip: '0.0.0.0' })).text()).toBe('Unauthorized')

    expect((await app.request('/rules', {}, { ip: '192.168.1.0' })).status).toBe(200)

    expect((await app.request('/rules', {}, { ip: '192.168.2.5' })).status).toBe(200)
    expect((await app.request('/rules', {}, { ip: '192.168.2.10' })).status).toBe(403)

    // /only-deny
    expect((await app.request('/only-deny', {}, { ip: '0.0.0.0' })).status).toBe(200)
    expect((await app.request('/only-deny', {}, { ip: '192.168.2.10' })).status).toBe(403)

    // /handlers
    expect((await app.request('/handlers', {}, { ip: '0.0.0.0' })).status).toBe(403)
    expect(await (await app.request('/handlers', {}, { ip: '0.0.0.0' })).text()).toBe('Denied')

    expect((await app.request('/handlers', {}, { ip: '192.168.1.0' })).status).toBe(200)

    expect((await app.request('/handlers', {}, { ip: '192.168.2.5' })).status).toBe(200)
    expect((await app.request('/handlers', {}, { ip: '192.168.2.10' })).status).toBe(403)

    expect((await app.request('/handlers', {}, { ip: '192.168.3.15' })).status).toBe(200)
    expect((await app.request('/handlers', {}, { ip: '192.168.3.20' })).status).toBe(403)
  })
})

describe('isMatchForRule', () => {
  it('IPv4 Wildcard', () => {
    expect(isMatchForRule({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.*')).toBeTruthy()
    expect(isMatchForRule({ addr: '192.168.3.1', type: 'IPv4' }, '192.168.2.*')).toBeFalsy()
  })
  it('CIDR Notation', () => {
    expect(isMatchForRule({ addr: '192.168.2.0', type: 'IPv4' }, '192.168.2.0/24')).toBeTruthy()
    expect(isMatchForRule({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.0/24')).toBeTruthy()

    expect(isMatchForRule({ addr: '::0', type: 'IPv6' }, '::0/1')).toBeTruthy()
  })
  it('Static Rules', () => {
    expect(isMatchForRule({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.1')).toBeTruthy()
    expect(isMatchForRule({ addr: '1234::5678', type: 'IPv6' }, '1234::5678')).toBeTruthy()
  })
})
