from django.db import models
from django.db.models.fields import (
    FilePathField,
    GenericIPAddressField,
    IPAddressField,
)


class DirectFilePathModel(models.Model):
    path = FilePathField()


class FilePathModel(models.Model):
    path = models.FilePathField()


class FieldsFilePathModel(models.Model):
    path = models.fields.FilePathField()


class DirectGenericIPAddressModel(models.Model):
    generic = GenericIPAddressField()


class GenericIPAddressModel(models.Model):
    generic = models.GenericIPAddressField()


class FieldsGenericIPAddressModel(models.Model):
    generic = models.fields.GenericIPAddressField()


class DirectIPAddressModel(models.Model):
    ip = IPAddressField()


class IPAddressModel(models.Model):
    ip = models.IPAddressField()


class FieldsIPAddressModel(models.Model):
    ip = models.fields.IPAddressField()
