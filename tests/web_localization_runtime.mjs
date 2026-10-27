// Optional dependency-free JavaScript smoke test. This checks script execution,
// not browser layout; the manual browser checklist is in Carriex/LOCALIZATION.md.
import vm from 'node:vm';
import assert from 'node:assert/strict';

class Element {
  constructor(tag, attrs = {}, text = '') {
    this.tagName = tag; this.attributes = attrs; this.textContent = text;
    this.dataset = {}; this.children = []; this.value = ''; this.className = attrs.class || '';
    for (const [name, value] of Object.entries(attrs)) if (name.startsWith('data-'))
      this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(name, value) { this.attributes[name] = value; }
}
const decode = text => text.replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

export async function checkPage(page, statistics = false, populated = false) {
  const elements = [...page.matchAll(/<([\w-]+)([^<>]*)>([^<]*)/g)].map(([, tag, source, text]) =>
    new Element(tag, Object.fromEntries([...source.matchAll(/([\w-]+)="([^"]*)"/g)].map(([, key, value]) => [key, decode(value)])), decode(text)));
  const byId = id => elements.find(e => e.attributes.id === id);
  const document = {
    documentElement: {}, getElementById: byId,
    querySelectorAll: selector => elements.filter(e => selector.slice(1, -1) in e.attributes),
    createElement: tag => new Element(tag), createElementNS: (_, tag) => new Element(tag),
  };
  const listeners = {};
  const window = {addEventListener: (name, handler) => { listeners[name] = handler; }, dispatchEvent: event => listeners[event.type]?.()};
  const metrics = populated ? {'messages.accepted': {total: 1234, samples: 2, mean: 617, minimum: 1, maximum: 1233}} : {};
  const data = {metrics, queue: {messages: 0, bytes: 0, available_prekeys: 0}, hourly: [], days: 7, retention_days: 30, collection_enabled: true, generated_at: new Date().toISOString()};
  const context = vm.createContext({document, window, navigator: {language: 'en'}, location: {search: ''},
    URLSearchParams, localStorage: {getItem: () => null, setItem: () => {}},
    Event: class {constructor(type) {this.type = type;}}, setInterval: () => {},
    fetch: async () => ({ok: true, json: async () => data}), Intl, Date, Map, Math, Array, Object, Error});
  for (const [, script] of page.matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInContext(script, context);
  await new Promise(resolve => setImmediate(resolve));
  const language = byId('carriex-language');
  assert.equal(document.documentElement.lang, 'en');
  if (statistics) {
    assert.equal(byId('cards').children[0].children[0].textContent, 'Accepted messages');
    assert(!byId('status').textContent.includes('Unable to load'), byId('status').textContent);
  }
  language.value = 'ru'; language.onchange();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(document.documentElement.lang, 'ru');
  if (statistics) {
    assert.equal(byId('cards').children[0].children[0].textContent, 'Принятые сообщения');
    assert(!byId('status').textContent.includes('Не удалось'), byId('status').textContent);
    assert.equal(byId('chart').children[0].textContent, 'За этот период принятые сообщения не зарегистрированы');
  } else {
    assert.equal(elements.find(e => e.tagName === 'textarea').attributes['aria-label'], 'Текст подключения');
  }
  language.value = 'en'; language.onchange();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(document.documentElement.lang, 'en');
}
