from .config import config
from .providers import VerificationError, CaptchaProvider
from flask import request, render_template
from functools import wraps
from lxml import etree
import logging
import os

logger = logging.getLogger('captcha')

def load(app):
    config(app)

    if not app.config['CAPTCHA_ENABLED']:
        return

    # Intitialize logging.
    logger.setLevel(app.config.get('LOG_LEVEL', "INFO"))

    log_dir = app.config.get('LOG_FOLDER', os.path.join(os.path.dirname(__file__), 'logs'))
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, 'captcha.log')

    if not os.path.exists(log_file):
        open(log_file, 'a').close()

    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10000)
    logger.addHandler(handler)
    logger.propagate = 0

    provider = CaptchaProvider.parse(app.config['CAPTCHA_PROVIDER'])(app.config['CAPTCHA_SITE_KEY'], app.config['CAPTCHA_SECRET'], app.config['CAPTCHA_VERIFY_REMOTE_IP'])

    def insert_tags(page):
        if isinstance(page, etree._ElementTree):
            root = page
        else:
            try:
                root = etree.fromstring(page, etree.HTMLParser())
            except:
                # We couldn't parse it (e.g. it is a Response object) so just pass it through
                return page

        # Insert the check box to the left of the submit button
        # Iterate through all forms adn buttons, but in reality there will only be one
        # unless the developer is doing a non-trivial custom theme
        # in which case they will turn off the automatic insert feature
        inserted_div, inserted_script = False, False
        for form in root.iter('form'):
            for button in form.xpath('.//button[@type="submit"] | .//input[@type="submit"]'):
                # Get the parent row div
                parent = button.getparent()
                row_parent = parent.getparent() if parent is not None else None
                
                # Create a wrapper div for captcha with proper Bootstrap classes
                captcha_wrapper = etree.Element('div', attrib={'class': 'row mb-3'})
                captcha_col = etree.Element('div', attrib={'class': 'col-12'})
                captcha_col.append(provider.challenge_tag())
                captcha_wrapper.append(captcha_col)
                
                # Insert before the button's row
                if row_parent is not None:
                    row_parent.addprevious(captcha_wrapper)
                else:
                    button.addprevious(provider.challenge_tag())
                    
                logger.debug("Inserted captcha checkbox element into page")
                inserted_div = True

        for head in root.iter('head'):
            head.append(provider.script_tag())
            logger.debug("Inserted captcha script tag into page head")
            inserted_script = True

        if not inserted_div and inserted_script:
            logger.error('Failed to insert capctha elements into page: inserted_div={!s}, inserted_script={!s}'.format(inserted_div, inserted_script))

        return etree.tostring(root, method='html')

    # Attempt to add an LRU cache to the insert function. If not available in the current runtime, continue.
    try:
        from functools import lru_cache
        insert_tags = lru_cache(maxsize=8)(insert_tags)
    except ImportError:
        pass

    def insert_tags_decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            return insert_tags(view_func(*args, **kwargs))

        return wrapper

    def register_decorator(register_func):
        @wraps(register_func)
        def wrapper(*args, **kwargs):
            if request.method == 'POST':
                errors = []
                verified = None
                try:
                    verified = provider.verify(request.form, request.remote_addr)
                except VerificationError as e:
                    errors.append("Captcha service is currently unavailable. Please try again later")

                if verified is False:
                    errors.append("Please check the captcha box to verify you are human")

                if not verified:
                    return render_template(
                        'register.html',
                        errors=errors,
                        name=request.form['name'],
                        email=request.form['email'],
                    )
            return register_func(*args, **kwargs)

        return wrapper

    def reset_password_decorator(reset_password_func):
        @wraps(reset_password_func)
        def wrapper(*args, **kwargs):
            if request.method == 'POST':
                errors = []
                verified = None
                try:
                    verified = provider.verify(request.form, request.remote_addr)
                except VerificationError as e:
                    errors.append("Captcha service is currently unavailable. Please try again later")

                if verified is False:
                    errors.append("Please check the captcha box to verify you are human")

                if not verified:
                    # Preserve the mode and data for reset password
                    mode = kwargs.get('data', None)
                    if mode:
                        return render_template(
                            'reset_password.html',
                            errors=errors,
                            mode='set',
                        )
                    else:
                        return render_template(
                            'reset_password.html',
                            errors=errors,
                            email=request.form.get('email', ''),
                        )
            return reset_password_func(*args, **kwargs)

        return wrapper

    app.view_functions['auth.register'] = register_decorator(app.view_functions['auth.register'])
    app.view_functions['auth.reset_password'] = reset_password_decorator(app.view_functions['auth.reset_password'])

    if app.config['CAPTCHA_INSERT_TAGS']:
        app.view_functions['auth.register'] = insert_tags_decorator(app.view_functions['auth.register'])
        app.view_functions['auth.reset_password'] = insert_tags_decorator(app.view_functions['auth.reset_password'])
