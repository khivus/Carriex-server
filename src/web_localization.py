"""Embedded EN/RU controls shared by the offline pairing page and dashboard."""
import html
import json


TRANSLATIONS = {
    "Carriex server pairing": "Подключение к серверу Carriex",
    "In Carriex, choose Scan server QR, or paste the text below using Import pairing text.":
        "В Carriex выберите «Сканировать QR-код сервера» или вставьте текст ниже через «Импортировать текст подключения».",
    "Carriex server pairing QR code": "QR-код подключения к серверу Carriex",
    "Server fingerprint:": "Отпечаток ключа сервера:",
    "Pairing text": "Текст подключения",
    "Select pairing text": "Выделить текст подключения",
    "This bundle contains only the public certificate. Share it through a trusted channel.":
        "Этот набор содержит только открытый сертификат. Передавайте его по доверенному каналу.",
    "Keep server-key.pem private and backed up. The address must be reachable from the phone.":
        "Храните server-key.pem в тайне и делайте резервную копию. Адрес должен быть доступен с телефона.",
    "Carriex · Relay statistics": "Carriex · Статистика сервера",
    "CARRIEX / PRACTICAL OBSERVATION": "CARRIEX / ПРАКТИЧЕСКИЕ НАБЛЮДЕНИЯ",
    "Relay statistics": "Статистика сервера",
    "Loading measurements…": "Загрузка измерений…",
    "Refresh": "Обновить",
    "Hourly measurements saved by this relay. Message contents, identities and private keys are not collected here.":
        "Почасовые измерения, сохранённые этим сервером. Содержимое сообщений, идентификаторы и закрытые ключи здесь не собираются.",
    "Accepted messages per hour · UTC": "Принятые сообщения по часам · UTC",
    "Accepted messages per hour": "Принятые сообщения по часам",
    "Measurements": "Измерения",
    "Metric": "Показатель", "Samples": "Измерений", "Total": "Сумма", "Mean": "Среднее", "Min": "Минимум", "Max": "Максимум",
    "Acknowledgement delay": "Задержка подтверждения",
    " runs from relay acceptance to recipient acknowledgement. It includes offline time, polling and client processing; it does not measure reading or isolated network latency. HTTP timing covers server handling only. Client encryption/decryption time is unavailable to the relay.":
        " измеряется от приёма сообщения сервером до подтверждения получателем. Она включает время без подключения, опрос и обработку клиентом; это не время прочтения и не отдельная сетевая задержка. Время HTTP отражает только обработку на сервере. Время шифрования и расшифровки на клиенте серверу неизвестно.",
    "This page refreshes every five seconds. Instrumentation adds SQLite work; compare performance using the same collection mode.":
        "Страница обновляется каждые пять секунд. Сбор измерений увеличивает нагрузку на SQLite; сравнивайте производительность при одинаковом режиме сбора.",
    "Server returned ": "Сервер вернул код ",
    "Accepted messages": "Принятые сообщения", "Recipient acknowledgements": "Подтверждения получателей",
    "Queued now": "Сейчас в очереди", "Queue bytes now": "Байт в очереди",
    "Claimed one-time keys": "Запрошенные одноразовые ключи", "Available keys now": "Доступные ключи",
    "No accepted messages recorded in this window": "За этот период принятые сообщения не зарегистрированы",
    "Collection configured: enabled": "Сбор измерений включён",
    "Collection configured: disabled (saved history remains)": "Сбор измерений отключён (история сохранена)",
    " · Updated ": " · Обновлено ",
    "Unable to load statistics: ": "Не удалось загрузить статистику: ",
    "Window: {days} days; configured retention: {retention} days": "Период, дней: {days}; срок хранения, дней: {retention}",
}


def localize_page(page: str) -> str:
    """No server round trips: also works for a copied file:// pairing.html."""
    encoded = json.dumps(TRANSLATIONS, ensure_ascii=True).replace("<", "\\u003c")
    controls = '''<div style="display:flex;justify-content:flex-end;margin:12px 0">
<label>Language / Язык <select id="carriex-language" aria-label="Language / Язык"><option value="en">English</option><option value="ru">Русский</option></select></label></div>'''
    script = '''<script>
(()=>{const translations=__TRANSLATIONS__,selector=document.getElementById('carriex-language');
let saved;try{saved=localStorage.getItem('carriex-language')}catch(_){}
const query=new URLSearchParams(location.search).get('lang');
let language=['en','ru'].includes(query)?query:(['en','ru'].includes(saved)?saved:(navigator.language.toLowerCase().startsWith('ru')?'ru':'en'));
const t=s=>language==='ru'?(translations[s]||s):s;
function apply(){document.documentElement.lang=language;selector.value=language;
document.querySelectorAll('[data-i18n]').forEach(e=>e.textContent=t(e.dataset.i18n));
document.querySelectorAll('[data-i18n-aria]').forEach(e=>e.setAttribute('aria-label',t(e.dataset.i18nAria)));
document.querySelectorAll('[data-i18n-alt]').forEach(e=>e.alt=t(e.dataset.i18nAlt));}
window.carriexI18n={t,get language(){return language}};
selector.onchange=()=>{language=selector.value;try{localStorage.setItem('carriex-language',language)}catch(_){}apply();window.dispatchEvent(new Event('carriex-language-change'))};apply();})();
</script>'''.replace("__TRANSLATIONS__", encoded)
    page = page.replace("</style>", "</style>" + controls, 1)
    if "<script>" in page:
        page = page.replace("<script>", script + "<script>", 1)
    else:
        page = page.replace("</html>", script + "</html>")
    return page


def translated_text(text: str) -> str:
    """Safe static text marker; user names and pairing payloads never enter this table."""
    escaped = html.escape(text)
    return f'<span data-i18n="{escaped}">{escaped}</span>'
