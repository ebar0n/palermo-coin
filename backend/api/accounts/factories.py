# -*- coding: utf-8 -*-
import factory
from faker import Factory as FakerFactory

from accounts.models import Account

faker = FakerFactory.create()


class AccountFactory(factory.django.DjangoModelFactory):

    class Meta:
        model = Account

    email = factory.LazyAttribute(lambda x: faker.email() + str(faker.unix_time()))
    first_name = factory.LazyAttribute(lambda x: faker.first_name())
    last_name = factory.LazyAttribute(lambda x: faker.last_name())
    phone_number = factory.LazyAttribute(lambda x: faker.phone_number())
    password = factory.LazyAttribute(lambda x: faker.password())
    is_active = True
