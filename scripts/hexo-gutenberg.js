'use strict'

hexo.extend.filter.register('before_post_render', data => {
  if (!data || !data.content) return data

  data.content = data.content.replace(/<figure class="highlight [^>]+>.*?<\/figure>/gs, match => {
    return match
      .replace(/<figure class="highlight [^"]+">/, '```')
  })

  return data
})
