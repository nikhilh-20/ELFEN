# Generated by Django 4.2.6 on 2023-12-17 15:29

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analysis', '0006_sendtoevent_recvfromevent'),
    ]

    operations = [
        migrations.AddField(
            model_name='detection',
            name='mitre_attack',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=1024), default=list, size=None),
        ),
    ]
