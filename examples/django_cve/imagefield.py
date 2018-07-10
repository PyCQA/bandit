from django import forms
from django.forms import ImageField


class DirectImageForm(forms.Form):
    image = ImageField()


class ImageForm(forms.Form):
    image = forms.ImageField()


class FieldImageForm(forms.Form):
    image = forms.fields.ImageField()
