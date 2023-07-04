from django import template
from django.utils.html import urlize

register = template.Library()

@register.filter
def urlize_link(value):
    return urlize(value, autoescape=True)
