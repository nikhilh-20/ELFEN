# Generated by Django 4.2.6 on 2024-03-02 07:55

import django.contrib.postgres.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0002_samplemetadata_similar'),
        ('analysis', '0009_alter_dnspacketanalysis_response_class_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='DnsQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.TimeField(null=True)),
                ('txid', models.PositiveIntegerField()),
                ('flags', models.PositiveIntegerField()),
                ('qdcount', models.PositiveSmallIntegerField()),
                ('ancount', models.PositiveSmallIntegerField()),
                ('nscount', models.PositiveSmallIntegerField()),
                ('arcount', models.PositiveSmallIntegerField()),
                ('rrsection', models.SmallIntegerField(choices=[('0', 'Question Section'), ('1', 'Answer Section'), ('2', 'Name Server Section'), ('3', 'Additional Records Section')], default=0)),
                ('query_domain', models.CharField(max_length=255, null=True)),
                ('query_type', models.CharField(max_length=8, null=True)),
                ('query_class', models.CharField(max_length=8, null=True)),
                ('opt_data', django.contrib.postgres.fields.ArrayField(base_field=models.JSONField(null=True), null=True, size=None)),
                ('errors', models.BooleanField(default=False)),
                ('error_msg', models.CharField(default='', max_length=4096)),
                ('status', models.SmallIntegerField(choices=[('0', 'Not Started'), ('1', 'In Progress'), ('2', 'Complete'), ('4', 'Error')], default=0)),
                ('pcapanalysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='analysis.pcapanalysis')),
                ('sample', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='web.samplemetadata')),
            ],
        ),
        migrations.CreateModel(
            name='DnsResponse',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.TimeField(null=True)),
                ('txid', models.PositiveIntegerField()),
                ('flags', models.PositiveIntegerField()),
                ('rcode', models.PositiveSmallIntegerField()),
                ('qdcount', models.PositiveSmallIntegerField()),
                ('ancount', models.PositiveSmallIntegerField()),
                ('nscount', models.PositiveSmallIntegerField()),
                ('arcount', models.PositiveSmallIntegerField()),
                ('rrsection', models.SmallIntegerField(choices=[('0', 'Question Section'), ('1', 'Answer Section'), ('2', 'Name Server Section'), ('3', 'Additional Records Section')], default=0, null=True)),
                ('response_type', models.CharField(max_length=8, null=True)),
                ('response_class', models.CharField(max_length=8, null=True)),
                ('response_ttl', models.IntegerField(null=True)),
                ('response_data', models.CharField(max_length=4096, null=True)),
                ('opt_data', django.contrib.postgres.fields.ArrayField(base_field=models.JSONField(null=True), null=True, size=None)),
                ('errors', models.BooleanField(default=False)),
                ('error_msg', models.CharField(default='', max_length=4096)),
                ('status', models.SmallIntegerField(choices=[('0', 'Not Started'), ('1', 'In Progress'), ('2', 'Complete'), ('4', 'Error')], default=0)),
                ('pcapanalysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='analysis.pcapanalysis')),
                ('sample', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='web.samplemetadata')),
            ],
        ),
        migrations.DeleteModel(
            name='DnsPacketAnalysis',
        ),
    ]
