from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0008_scanjob_scanfinding"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="notification_email",
            field=models.EmailField(blank=True, max_length=254),
        ),
        migrations.AddField(
            model_name="scanjob",
            name="notification_attempted_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="scanjob",
            name="notification_sent_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="scanjob",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("running", "Running"),
                    ("completed", "Completed"),
                    ("failed", "Failed"),
                    ("blocked", "Blocked"),
                ],
                default="pending",
                max_length=12,
            ),
        ),
    ]
