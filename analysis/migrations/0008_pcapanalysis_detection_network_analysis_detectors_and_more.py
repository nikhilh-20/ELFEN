# Generated by Django 4.2.6 on 2023-12-25 07:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0001_initial'),
        ('analysis', '0007_detection_mitre_attack'),
    ]

    operations = [
        migrations.CreateModel(
            name='PcapAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('errors', models.BooleanField(default=False)),
                ('error_msg', models.CharField(default='', max_length=4096)),
                ('status', models.SmallIntegerField(choices=[('0', 'Not Started'), ('1', 'In Progress'), ('2', 'Complete'), ('4', 'Error')], default=0)),
            ],
        ),
        migrations.AddField(
            model_name='detection',
            name='network_analysis_detectors',
            field=models.JSONField(null=True),
        ),
        migrations.AddField(
            model_name='detection',
            name='network_analysis_score',
            field=models.SmallIntegerField(null=True),
        ),
        migrations.CreateModel(
            name='DnsPacketAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.TimeField(null=True)),
                ('query_domain', models.CharField(max_length=255)),
                ('query_type', models.CharField(max_length=8)),
                ('query_class', models.CharField(max_length=8)),
                ('response_type', models.CharField(max_length=8)),
                ('response_class', models.CharField(max_length=8)),
                ('response_ttl', models.IntegerField()),
                ('response_data', models.CharField(max_length=256)),
                ('pcapanalysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='analysis.pcapanalysis')),
                ('sample', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='web.samplemetadata')),
            ],
        ),
        migrations.AddField(
            model_name='networkanalysisreports',
            name='pcapanalysis',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.PROTECT, to='analysis.pcapanalysis'),
        ),
    ]
