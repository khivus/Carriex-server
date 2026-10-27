<!-- English source SHA256: 618bc224ab973d471657e48b7d4853b4b6b490d34771636f8aecfb9effad4828 -->
# Участие в разработке

[English](CONTRIBUTING.md) | **Русский**

Создайте ветку и установите зависимости разработки по README. Делайте изменения целенаправленно и добавляйте интеграционные тесты при изменении поведения API.

```sh
python -m ruff check .
python -m pytest -q
python -m build
```

При изменении контейнеров также выполните `docker compose up --build -d`, проверьте `/health` и журналы, затем `docker compose down`.

Пользовательские изменения описывайте в разделе `Unreleased` файла `CHANGELOG.md` и его русском варианте. Меняйте `src/_version.py` только при подготовке выпуска по процедуре README. В pull request включайте описание изменений и результаты проверок.
