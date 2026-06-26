from django.core.management.base import BaseCommand
from django.db import connection

from mobsf.StaticAnalyzer.models import ApkEditorSession


class Command(BaseCommand):
    help = 'Ensure APK editor database tables exist.'

    def handle(self, *args, **options):
        table_name = ApkEditorSession._meta.db_table
        if table_name in connection.introspection.table_names():
            self.stdout.write(f'APK editor table exists: {table_name}')
            return

        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(ApkEditorSession)

        self.stdout.write(
            self.style.SUCCESS(f'Created APK editor table: {table_name}'),
        )
