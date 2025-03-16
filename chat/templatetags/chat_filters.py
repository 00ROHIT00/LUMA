from django import template

register = template.Library()

@register.filter
def contains(queryset, obj):
    return obj in queryset 