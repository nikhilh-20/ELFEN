# Generated by Django 4.1.7 on 2023-08-18 19:49

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='SampleMetadata',
            fields=[
                ('md5', models.CharField(max_length=32)),
                ('sha1', models.CharField(max_length=40)),
                ('sha256', models.CharField(max_length=64, primary_key=True, serialize=False)),
                ('bintype', models.CharField(choices=[('et_none', 'ET_NONE'), ('et_rel', 'ET_REL'), ('et_exec', 'ET_EXEC'), ('et_dyn', 'ET_DYN'), ('et_core', 'ET_CORE')], max_length=7, null=True)),
                ('tlsh', models.CharField(max_length=72, null=True)),
                ('family', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=64), default=list, size=None)),
                ('tags', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=64), default=list, size=None)),
                ('username', models.CharField(max_length=150)),
            ],
        ),
        migrations.AddConstraint(
            model_name='samplemetadata',
            constraint=models.CheckConstraint(check=models.Q(('bintype__in', ['et_none', 'et_rel', 'et_exec', 'et_dyn', 'et_core'])), name='web_samplemetadata_bintype_valid'),
        ),
    ]