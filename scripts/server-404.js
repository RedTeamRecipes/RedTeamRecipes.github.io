'use strict'

hexo.extend.filter.register('server_middleware', app => {
  app.use((req, res, next) => {
    const route = hexo.route.get('404.html')
    if (!route) return next()

    res.statusCode = 404
    res.setHeader('Content-Type', 'text/html; charset=utf-8')

    const stream = typeof route === 'function' ? route() : route
    try {
      stream.pipe(res)
    } catch (err) {
      res.end('404 Not Found')
    }
  })
})
