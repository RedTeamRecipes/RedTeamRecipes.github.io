'use strict'

hexo.extend.filter.register('after_render:html', str => {
  if (typeof str !== 'string') return str
  return str
    .replace(/```\s*(<figure class="my-table">)/g, '$1')
    .replace(/(<\/figure><\/figure>)\s*```/g, '$1')
})
