# Generated by Django 5.1.6 on 2025-03-29 03:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0020_deletedgroupmessage_groupmessagereport'),
    ]

    operations = [
        migrations.AddField(
            model_name='groupmessage',
            name='is_encrypted',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='message',
            name='is_encrypted',
            field=models.BooleanField(default=True),
        ),
    ]
