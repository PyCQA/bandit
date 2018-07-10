from django import forms
from django.forms.models import ModelMultipleChoiceField


class MultipleChoiceForm(forms.Form):
    members = forms.ModelMultipleChoiceField()


class MultipleChoiceVulnerableForm(forms.Form):
    members = forms.ModelMultipleChoiceField(show_hidden_initial=True)


class DirectMultipleChoiceVulnerableForm(forms.Form):
    members = ModelMultipleChoiceField(show_hidden_initial=True)
