'use strict'

const TYPE_MAP = {
  info: { label: 'Info', color: '#ff6b6b' },
  note: { label: 'Note', color: '#d5d5d5' },
  tip: { label: 'Tip', color: '#ff9770' },
  success: { label: 'Success', color: '#ff9770' },
  warning: { label: 'Warning', color: '#ffc15e' },
  danger: { label: 'Danger', color: '#ff4d4d' },
  alert: { label: 'Alert', color: '#ff4d4d' }
}

const CALLOUT_REGEX = /^:::([a-zA-Z]+)\s*\n([\s\S]+?)\n:::/gm

hexo.extend.filter.register('before_post_render', data => {
  if (!data || !data.content) return data

  data.content = data.content.replace(CALLOUT_REGEX, (match, rawType, body) => {
    const type = rawType.toLowerCase()
    const meta = TYPE_MAP[type] || { label: type.toUpperCase(), color: '#ff6b6b' }
    const inner = body.trim()
    return `\n<div class="md-callout md-callout-${type}" data-callout="${type}">\n<p class="md-callout__title" style="color:${meta.color}">${meta.label}</p>\n<div class="md-callout__body">\n${inner}\n</div>\n</div>\n`
  })

  return data
})
