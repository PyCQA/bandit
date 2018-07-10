from django import forms
from django.forms.formsets import BaseFormSet, formset_factory
from django.shortcuts import render


class LinkForm(forms.Form):
    url = forms.URLField()


def test_profile_settings(request):
    LinkFormSet = formset_factory(LinkForm, formset=BaseFormSet)

    if request.method == 'POST':
        link_formset = LinkFormSet(request.POST)
    else:
        link_formset = LinkFormSet()

    context = {
        'link_formset': link_formset,
    }

    return render(request, 'template.html', context)
