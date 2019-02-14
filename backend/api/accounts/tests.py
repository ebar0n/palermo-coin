# -*- coding: utf-8 -*-
import base64
import json

import pytest
from django.conf import settings
from django.core import mail
from django.utils import translation
from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from accounts import factories
from accounts.models import Account

translation.activate(factories.faker.random_element(settings.LANGUAGES)[0])


@pytest.fixture
def client():
    """
    Fixture responsible for build the api client
    Returns APIClient object:

    """
    return APIClient()


@pytest.fixture
def url():
    """
    Fixture responsible for build the api url for main endpoint
    Returns Func:

    """
    return reverse('accounts-list')


@pytest.fixture
def url_login():
    """
    Fixture responsible for build the api url for login endpoint
    Returns Func:

    """
    return reverse('login')


@pytest.fixture
def url_logout():
    """
    Fixture responsible for build the api url for logout endpoint
    Returns Func:

    """
    return reverse('logout')


@pytest.fixture
def url_detail():
    """
    Fixture responsible for build the api url for detail endpoint
    Returns Func:

    """

    def wrapper(pk):
        """
        Wrapper

        """
        return reverse('accounts-detail', args=[pk])

    return wrapper


@pytest.fixture
def url_change_password():
    """
    Fixture responsible for build the api url for change password endpoint
    Returns Func:
    """

    def wrapper(pk):
        """
        Wrapper

        """
        return reverse('accounts-change-password', args=[pk])

    return wrapper


@pytest.fixture
def admin_account():
    """
    Fixture responsible for build an admin account
    Returns Account Object:

    """
    obj = factories.AccountFactory.create()
    obj.decrypt_password = obj.password
    obj.set_password(obj.password)
    obj.is_staff = True
    obj.is_admin = True
    obj.save()
    return obj


@pytest.fixture
def account():
    """
    Fixture responsible for build an account
    Returns Account Object:

    """
    obj = factories.AccountFactory.create()
    obj.decrypt_password = obj.password
    obj.set_password(obj.password)
    obj.save()
    return obj


@pytest.fixture
def client_auth(client, url_login, account, monkeypatch):
    """
    Fixture responsible for build the api client to auth
    Returns APIClient object:

    """
    data = {
        'email': account.email,
        'password': account.decrypt_password
    }
    request = client.post(path=url_login, data=data, format='json')
    assert request.status_code == status.HTTP_200_OK
    return client


@pytest.fixture
def accounts():
    """
    Fixture responsible for build a list of accounts
    Returns List of Account Objects:

    """
    return factories.AccountFactory.create_batch


########################
# Auth (login, logout) #
########################


@pytest.mark.django_db
def test_login_succesfull(client, url_login, url_detail, account, monkeypatch):
    """
    Testing to login service

    Args:
        client: ApiClient
        url_login:  Endpoint Url
        url_detail: Endpoint Url
        account: Create Account object
        monkeypatch: Mock
    """
    data = {
        'email': account.email,
        'password': account.decrypt_password
    }
    request = client.post(path=url_login, data=data, format='json')
    assert request.status_code == status.HTTP_200_OK
    assert request.data.get('id') is not None, 'User not logged'
    assert request.data.get('email') is not None, 'User not logged'
    assert request.data.get('token') is not None, 'Not create token'

    request = client.get(path=url_detail(request.data.get('id')), format='json')
    assert request.status_code == status.HTTP_200_OK, 'Fails to retrieve account'
    assert '_auth_user_id' in client.session._session, 'User is authenticated'


@pytest.mark.django_db
def test_login_failed_login(client, url_login):
    """
    Testing to login service with invalid credentials

    Args:
        client: ApiClient
        url_login:  Endpoint Url
        account: Create Account object

    """
    data = {
        'email': 'test_email@test.com',
        'password': 'test_password'
    }
    request = client.post(path=url_login, data=data, format='json')
    assert request.status_code == status.HTTP_401_UNAUTHORIZED, 'Fails to login account'
    assert '_auth_user_id' not in client.session._session, 'User is authenticated'


@pytest.mark.django_db
def test_login_failed_login_credentials(client, url_login, account, monkeypatch):
    """
    Testing to login service with invalid credentials

    Args:
        client: ApiClient
        url_login:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock

    """
    data = {
        'email': 'test_email@test.com',
        'password': 'test_password'
    }
    request = client.post(path=url_login, data=data, format='json')
    assert request.status_code == status.HTTP_401_UNAUTHORIZED, 'Fails to login account'
    assert request.data.get('message') == _('Username/password combination invalid.'), 'Unauthorized'
    assert '_auth_user_id' not in client.session._session, 'User is authenticated'


@pytest.mark.django_db
def test_logout_succesfull(client_auth, url_logout, account):
    """
    Testing to logout service

    Args:
        client: ApiClient
        url_logout:  Endpoint Url
        account: Create Account object

    """
    request = client_auth.post(path=url_logout, format='json')
    assert request.status_code == status.HTTP_204_NO_CONTENT
    assert '_auth_user_id' not in client_auth.session._session, 'User is authenticated'


@pytest.mark.django_db
def test_logout_failed_credentials(client, url_logout):
    """
    Testing to logout service with invalid credentials

    Args:
        client: ApiClient
        url_logout:  Endpoint Url

    """
    request = client.post(path=url_logout, format='json')
    assert request.status_code == status.HTTP_403_FORBIDDEN, 'Fails to login account'
    assert request.data.get('detail') == _('Authentication credentials were not provided.'), 'User is logged'
    assert '_auth_user_id' not in client.session._session, 'User is authenticated'


############
# Accounts #
############


@pytest.mark.django_db
def test_client_add_account_valid(client, url, monkeypatch):
    """
    Testing add new account correctly

    Args:
        client: ApiClient
        url:  Endpoint Url,
        monkeypatch: Mock

    """
    data = {
        'email': factories.faker.email(),
        'first_name': factories.faker.first_name(),
        'last_name': factories.faker.last_name(),
        'password': factories.faker.password(),
    }
    request = client.post(path=url, data=data, format='json')
    obj = Account.objects.get(email=data.get('email'))
    assert request.status_code == status.HTTP_201_CREATED, 'Fails to create account'
    assert Account.objects.count() == 1, 'Count is different in db'
    assert obj.check_password(data.get('password')) is True, 'The password do not match'
    assert obj.email == data.get('email'), 'The email do not match'
    assert '_auth_user_id' in client.session._session, 'User is unauthenticaded'


@pytest.mark.django_db
def test_client_add_account_valid_with_full_data(client, url, account, monkeypatch):
    """
    Testing add new account correctly

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock
    """
    data = {
        'email': factories.faker.email(),
        'first_name': factories.faker.first_name(),
        'last_name': factories.faker.last_name(),
        'password': factories.faker.password(),
    }

    request = client.post(path=url, data=data, format='json')
    obj = Account.objects.get(email=data.get('email'))
    assert request.status_code == status.HTTP_201_CREATED, 'Fails to create account'
    assert Account.objects.count() == 2
    assert obj.check_password(data.get('password')) is True, 'The password do not match'
    assert obj.email == data.get('email'), 'The email do not match'
    assert '_auth_user_id' in client.session._session, 'User is unauthenticaded'


@pytest.mark.django_db
def test_client_add_account_invalid_first_name(client, url, account):
    """
    Testing add account without first_name

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object

    """
    data = {'first_name': '', 'email': factories.faker.email()}
    request = client.post(path=url, data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Error code must be 400'
    assert Account.objects.count() == 1, 'Incorrect number objects of account'


@pytest.mark.django_db
def test_client_add_account_invalid_password(client, url, account, monkeypatch):
    """
    Testing add account without first_name

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock
    """
    data = {
        'email': factories.faker.email(),
        'first_name': factories.faker.first_name(),
        'last_name': factories.faker.last_name(),
        'phone_number': factories.faker.phone_number(),
        'password': '',
    }

    request = client.post(path=url, data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Error code must be 400'
    assert request.data.get('password')[0] == _('This field is required.'), 'Failed password not empty'

    data['password'] = '123456'
    request = client.post(path=url, data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Error code must be 400'
    assert request.data.get('password')[0] == _(
        _('Must be at least 8 characters')
    ), 'Failed password'

    data['password'] = 'aaaaaaaa'
    request = client.post(path=url, data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Error code must be 400'
    assert request.data.get('password')[0] == _(
        _('Must include a number')
    ), 'Failed password'

    data['password'] = '12345678'
    request = client.post(path=url, data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Error code must be 400'
    assert request.data.get('password')[0] == _(
       _('Must include a capital letter')
    ), 'Failed password'

    data['password'] = '123aAa789'
    request = client.post(path=url, data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Error code must be 400'
    assert request.data.get('password')[0] == _(
        _('Must include a special character')
    ), 'Failed password'


@pytest.mark.django_db
def test_client_retrieve_account(client_auth, url, url_detail):
    """
    Testing retrieve account

    Args:
        client_auth: ApiClient
        url_detail:  Endpoint Url
        admin_account: Create Account object

    """
    request = client_auth.get(path=url + 'get_account/', format='json')
    assert request.status_code == status.HTTP_200_OK, 'Fails to retrieve account'

    request = client_auth.get(path=url_detail(request.data.get('id')), format='json')
    obj = Account.objects.get(email=request.data.get('email'))
    assert request.status_code == status.HTTP_200_OK, 'Fails to retrieve account'
    assert obj.email == request.data.get('email'), 'Incorrect value field email'


@pytest.mark.django_db
def test_client_update_account_success(client_auth, url, url_detail):
    """
    Testing update account

    Args:
        client_auth: ApiClient
        url:  Endpoint Url
        url_detail:  Endpoint Url

    """
    request = client_auth.get(path=url + 'get_account/', format='json')
    account_current = Account.objects.get(email=request.data.get('email'))

    data = {
        'first_name': factories.faker.first_name(),
        'last_name': factories.faker.last_name(),
        'email': account_current.email,
        'password': factories.faker.password(),
    }
    request = client_auth.put(path=url_detail(account_current.pk), data=data, format='json')
    obj = Account.objects.get(pk=account_current.pk)
    assert request.status_code == status.HTTP_200_OK, 'Fails to update account'
    assert obj.check_password(data.get('password')) is False, 'Incorrect value field password'
    assert obj.email == data.get('email'), 'Incorrect value field email'


@pytest.mark.django_db
def test_client_update_account_failed(client_auth, url, url_detail, admin_account):
    """
    Testing update account

    Args:
        client_auth: ApiClient
        url:  Endpoint Url
        url_detail:  Endpoint Url
        admin_account: Create Account object
        account: Create Account object

    """
    request = client_auth.get(path=url + 'get_account/', format='json')
    account_current = Account.objects.get(email=request.data.get('email'))

    data = {}
    request = client_auth.put(path=url_detail(admin_account.pk), data=data, format='json')
    assert request.status_code == status.HTTP_403_FORBIDDEN, 'Unauthenticated user'

    assert client_auth.login(
        username=admin_account.username,
        password=admin_account.decrypt_password
    ) is True, 'Failed login'
    data = {}
    request = client_auth.put(path=url_detail(admin_account.pk), data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Invalid values in fields object account'
    assert request.data.get('email')[0] == _('This field is required.'), 'Incorrect value field email'

    data = {
        'email': account_current.email,
    }
    request = client_auth.put(path=url_detail(admin_account.pk), data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Invalid values email in object account'
    assert request.data.get('email')[0] == _('account with this email already exists.'), 'Incorrect value field email'


@pytest.mark.django_db
def test_client_partial_update_account_with_data(client_auth, url, url_detail):
    """
    Testing update account

    Args:
        client: ApiClient
        url:  Endpoint Url
        url_detail:  Endpoint Url
        account: Create Account object

    """
    request = client_auth.get(path=url + 'get_account/', format='json')
    account_current = Account.objects.get(email=request.data.get('email'))

    data = {
        'first_name': factories.faker.first_name(),
    }
    request = client_auth.patch(path=url_detail(account_current.pk), data=data, format='json')
    assert request.status_code == status.HTTP_200_OK, 'Fails to update partial account'
    assert account_current.first_name != request.data.get('first_name'), 'Incorrect value field first_name'
    assert account_current.email == request.data.get('email'), 'Incorrect value field email'


@pytest.mark.django_db
def test_client_partial_update_account_without_data(client_auth, url, url_detail):
    """
    Testing update account

    Args:
        client_auth: ApiClient
        url:  Endpoint Url
        url_detail:  Endpoint Url
        account: Create Account object

    """
    request = client_auth.get(path=url + 'get_account/', format='json')
    account_current = Account.objects.get(email=request.data.get('email'))
    data = {}
    request = client_auth.patch(path=url_detail(account_current.pk), data=data, format='json')
    assert request.status_code == status.HTTP_200_OK, 'Fails to update partial account'


@pytest.mark.django_db
def test_client_delete(client_auth, url, url_detail):
    """
    Testing delete account

    Args:
        client: ApiClient
        url:  Endpoint Url
        url_detail:  Endpoint Url

    """
    request = client_auth.get(path=url + 'get_account/', format='json')
    account_current = Account.objects.get(email=request.data.get('email'))

    request = client_auth.delete(path=url_detail(account_current.pk), format='json')
    assert request.status_code == status.HTTP_204_NO_CONTENT, 'Fails to delete account'
    assert Account.objects.filter(is_active=True).count() == 0, 'Incorrect number objects of account'


@pytest.mark.django_db
def test_client_delete_fail(client, url_detail, account):
    """
    Testing delete user failed when the user is not logged.

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object

    """
    assert '_auth_user_id' not in client.session._session, _('User is authenticated')
    request = client.delete(path=url_detail(account.pk), format='json')
    assert request.status_code == status.HTTP_403_FORBIDDEN, 'Not fails to delete account'
    assert Account.objects.count() == 1, 'Incorrect number objects of account'


@pytest.mark.django_db
def test_client_list_of_accounts(client, url, accounts, admin_account, account, monkeypatch):
    """
    Testing list of accounts

    Args:
        client: ApiClient
        url:  Endpoint Url
        accounts: function to create a list of objects
        admin_account: Create Account object
        account: Create Account object
        monkeypatch: Mock

    """
    # Create N objects
    number_of_objects = factories.faker.random_digit_not_null()
    accounts(number_of_objects)

    request = client.get(path=url, format='json')
    assert request.status_code == status.HTTP_403_FORBIDDEN, 'Not fails to list account'

    assert client.login(
        username=account.username,
        password=account.decrypt_password
    ) is True, 'Failed login'
    assert request.status_code == status.HTTP_403_FORBIDDEN, 'Not fails to list account'

    assert client.login(
        username=admin_account.username,
        password=admin_account.decrypt_password
    ) is True, 'Failed login'
    request = client.get(path=url, format='json')

    assert request.status_code == status.HTTP_200_OK, 'Fails to list accounts'
    assert request.data.get('count') == Account.objects.count(), 'Incorrect number objects in data'


##################
# Reset Password #
##################


@pytest.mark.django_db
def test_reset_password_succesfull(client, url, account, monkeypatch):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock
    """
    data = {'email': account.email}
    request = client.post(path=url + 'reset_password_ask/', data=data, format='json')
    assert request.status_code == status.HTTP_204_NO_CONTENT, 'Fails to reset password for account'

    assert len(mail.outbox) == 1, 'Incorrect number of emails'
    assert len(mail.outbox[0].to) == 1, 'Incorrect number of addressees'

    outbox = mail.outbox[0].alternatives[0][0]

    assert account.get_full_name() in outbox, 'Incorrect email of account'

    url_reset = outbox.split('<a href="')[1].split('"')[0]
    data_json = json.loads(
        base64.urlsafe_b64decode(url_reset.split('/')[-2]).decode('utf8')
    )

    data['token'] = data_json['token']
    data['password'] = factories.faker.password()
    assert client.login(
        username=account.username,
        password=data['password']
    ) is False, 'Do not fail on login using an incorrect password'

    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.status_code == status.HTTP_204_NO_CONTENT, 'Fails to change password of reset accounts'

    assert client.login(
        username=account.username,
        password=data['password']
    ) is True, 'Failed login'


@pytest.mark.django_db
def test_reset_password_fail_without_data(client, url):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url

    """
    request = client.post(path=url + 'reset_password_ask/', data={}, format='json')
    assert request.data.get('errors').get('email')[0] == _('This field is required.'), 'Incorrect value field email'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_fail_user_does_not_exist(client, url):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url

    """
    data = {'email': factories.faker.email()}
    request = client.post(path=url + 'reset_password_ask/', data=data, format='json')
    assert request.status_code == status.HTTP_404_NOT_FOUND, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_fail_already_send(client, url, account, monkeypatch):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock

    """
    data = {'email': account.email}
    request = client.post(path=url + 'reset_password_ask/', data=data, format='json')
    assert request.status_code == status.HTTP_204_NO_CONTENT, 'Fails reset password'

    request = client.post(path=url + 'reset_password_ask/', data=data, format='json')
    assert request.data.get('message') == _('We already sent a link to reset the password.'), 'Incorrect message error'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_change_fail_without_data(client, url):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url

    """
    data = {}
    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.data.get('errors').get('email')[0] == _('This field is required.'), 'Incorrect value field email'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_change_fail_without_password_and_token(client, url, account):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object

    """
    data = {'email': account.email}
    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.data.get('errors').get('token')[0] == _('This field is required.'), 'Incorrect value field token'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_change_fail_without_password(client, url, account):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object

    """
    data = {'email': account.email, 'token': factories.faker.md5()}
    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.data.get('errors')['password'][0] == _('This field is required.'), 'Incorrect value field password'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_change_user_does_not_exist(client, url):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url

    """
    data = {
        'email': factories.faker.email(),
        'token': factories.faker.md5(),
        'password': factories.faker.password()
    }
    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.status_code == status.HTTP_404_NOT_FOUND, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_change_token_does_not_match(client, url, account, monkeypatch):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock

    """
    data = {
        'email': account.email,
        'token': factories.faker.md5(),
        'password': factories.faker.password()
    }
    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.data.get('message') == _('Token does not match with the account.'), 'Correct value field token'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


@pytest.mark.django_db
def test_reset_password_change_token_invalid_password(client, url, account, monkeypatch):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock

    """
    data = {
        'email': account.email,
        'token': factories.faker.md5(),
        'password': '123456'
    }
    request = client.post(path=url + 'reset_password_change/', data=data, format='json')
    assert request.data.get('errors', {}).get('password')[0] == _(
        'Must be at least 8 characters'
    ), 'Correct value field token'
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Not fails reset password'


###################
# Change Password #
###################


@pytest.mark.django_db
def test_change_password_succesfull(client, url_change_password, account, monkeypatch):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock

    """
    assert client.login(
        username=account.username,
        password=account.decrypt_password
    ) is True, 'Failed login'

    data = {
        'old_password': account.decrypt_password,
        'new_password': factories.faker.password()
    }
    request = client.post(path=url_change_password(account.pk), data=data, format='json')
    assert request.status_code == status.HTTP_204_NO_CONTENT, 'Fails change password'

    account_db = Account.objects.get(pk=account.pk)
    assert account_db.check_password(data['new_password']) is True, 'Fails compared password'

    assert client.login(
        username=account.username,
        password=account.decrypt_password
    ) is False, 'Not Failed login'

    assert client.login(
        username=account_db.username,
        password=data['new_password']
    ) is True, 'Failed login'


@pytest.mark.django_db
def test_change_password_failed(client, url_change_password, account, monkeypatch):
    """
    Testing to reset password service

    Args:
        client: ApiClient
        url:  Endpoint Url
        account: Create Account object
        monkeypatch: Mock

    """
    data = {
        'old_password': account.decrypt_password,
        'new_password': factories.faker.password()
    }
    request = client.post(path=url_change_password(account.pk), data=data, format='json')
    assert request.status_code == status.HTTP_403_FORBIDDEN, 'Unauthenticated user'

    assert client.login(
        username=account.username,
        password=account.decrypt_password
    ) is True, 'Failed login'

    data['old_password'] = factories.faker.password()
    request = client.post(path=url_change_password(account.pk), data=data, format='json')
    assert request.status_code == status.HTTP_400_BAD_REQUEST, 'Incorrect change password for field to value'


##################
# Check Password #
##################


@pytest.mark.django_db
def test_check_email(client, url, account):
    """
    Testing to check email service

    Args:
        client: ApiClient
        url: Endpoint Url
        account: Create Account object

    """
    data = {
        'email': account.email
    }
    request = client.post(path=url + 'check_email/', data=data, format='json')
    assert request.status_code == status.HTTP_406_NOT_ACCEPTABLE, 'Fails to request, Email not exists'

    data = {
        'email': 'trash' + account.email
    }
    request = client.post(path=url + 'check_email/', data=data, format='json')
    assert request.status_code == status.HTTP_200_OK, 'Fails to request, Email exists'
