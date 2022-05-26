# InteractiveSSO-Captcha
Captcha system for InteractiveSSO


[Document](https://www.interactiveplus.org/TechDocs/InteractiveSSO/SimpleCaptcha/SimpleCaptcha.html)

## Usage

```bash
./interactivesso-captcha -conf "config.json"
```

Can also modify environment variable $PORT, $SECRET_KEY, $REDIS_ADDR, $REDIS_PORT, and $REDIS_PASSWORD to change config.

```bash
heroku stack:set container
git push heroku main
```
