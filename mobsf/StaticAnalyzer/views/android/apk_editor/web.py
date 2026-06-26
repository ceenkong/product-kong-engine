import logging
from functools import wraps

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.forms import UploadFileForm
from mobsf.MobSF.views.authentication import login_required
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)
from mobsf.MobSF.views.helpers import FileType
from mobsf.MobSF.views.home import file_download
from mobsf.MobSF.views.scanning import handle_uploaded_file
from mobsf.StaticAnalyzer.views.android.apk_editor.build import (
    save_session,
    saved_output_path,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.frida import (
    inject_frida_gadget,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.obfuscation import (
    obfuscate_session,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    discard_session,
    get_editor_status,
    read_session_logs,
    start_session,
)


logger = logging.getLogger(__name__)
GENERIC_ERROR = 'APK editor operation failed'


def json_error(message, status=400):
    return JsonResponse(
        {'status': 'failed', 'error': message},
        status=status,
    )


def request_value(request, name):
    return request.GET.get(name) or request.POST.get(name)


def handle_service_error(exp):
    if isinstance(exp, ValueError):
        return json_error(str(exp), 400)
    logger.exception('APK editor operation failed')
    return json_error(GENERIC_ERROR, 500)


def scan_permission_required(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if has_permission(request, Permissions.SCAN, api=False):
            return view(request, *args, **kwargs)
        return json_error('Permission denied', 403)
    return wrapper


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['GET'])
def editor(request):
    return render(
        request,
        'static_analysis/apk_editor.html',
        {
            'title': 'APK Editor',
            'version': settings.MOBSF_VER,
            'md5': '',
            'app_type': '',
            'apk_editor_standalone': True,
        },
    )


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['POST'])
def upload(request):
    form = UploadFileForm(request.POST, request.FILES)
    if not form.is_valid():
        return json_error('Invalid Form Data', 422)

    file_obj = request.FILES['file']
    file_type = FileType(file_obj)
    if not file_type.is_allow_file() or not file_type.is_apk():
        return json_error('Only APK files are supported', 400)

    try:
        source_md5 = handle_uploaded_file(file_obj, '.apk')
        return JsonResponse(start_session(source_md5))
    except Exception as exp:
        return handle_service_error(exp)


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['POST'])
def start(request):
    source_md5 = request.POST.get('hash')
    if not source_md5:
        return json_error('Missing hash', 422)

    try:
        return JsonResponse(start_session(source_md5))
    except Exception as exp:
        return handle_service_error(exp)


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['GET', 'POST'])
def status(request):
    source_md5 = request_value(request, 'hash')
    session_id = request_value(request, 'session_id')
    if not source_md5:
        return json_error('Missing hash', 422)

    try:
        return JsonResponse(get_editor_status(source_md5, session_id))
    except Exception as exp:
        return handle_service_error(exp)


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['POST'])
def discard(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return json_error('Missing hash', 422)
    if not session_id:
        return json_error('Missing session_id', 422)

    try:
        return JsonResponse(discard_session(source_md5, session_id))
    except Exception as exp:
        return handle_service_error(exp)


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['POST'])
def frida_gadget(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return json_error('Missing hash', 422)
    if not session_id:
        return json_error('Missing session_id', 422)

    try:
        abis = request.POST.getlist('abis') or None
        return JsonResponse(inject_frida_gadget(source_md5, session_id, abis))
    except Exception as exp:
        return handle_service_error(exp)


def obfuscation_options(request):
    return {
        'smali': request.POST.get('smali') == '1',
        'assets': request.POST.get('assets') == '1',
        'resources': request.POST.get('resources') == '1',
        'anti_analysis': request.POST.get('anti_analysis') == '1',
        'frida_hide': request.POST.get('frida_hide') == '1',
    }


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['POST'])
def obfuscate(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return json_error('Missing hash', 422)
    if not session_id:
        return json_error('Missing session_id', 422)

    try:
        return JsonResponse(obfuscate_session(
            source_md5,
            session_id,
            obfuscation_options(request),
        ))
    except Exception as exp:
        return handle_service_error(exp)


@csrf_protect
@login_required
@scan_permission_required
@require_http_methods(['POST'])
def save(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return json_error('Missing hash', 422)
    if not session_id:
        return json_error('Missing session_id', 422)

    try:
        return JsonResponse(save_session(
            source_md5,
            session_id,
            {'signing': request.POST.get('signing') or 'debug'},
        ))
    except Exception as exp:
        return handle_service_error(exp)


@login_required
@scan_permission_required
@require_http_methods(['GET'])
def download(request):
    source_md5 = request.GET.get('hash')
    session_id = request.GET.get('session_id')
    if not source_md5:
        return json_error('Missing hash', 422)
    if not session_id:
        return json_error('Missing session_id', 422)

    try:
        output_path = saved_output_path(source_md5, session_id)
        return file_download(
            output_path,
            output_path.name,
            'application/octet-stream',
        )
    except Exception as exp:
        return handle_service_error(exp)


@login_required
@scan_permission_required
@require_http_methods(['GET'])
def logs(request):
    source_md5 = request.GET.get('hash')
    session_id = request.GET.get('session_id')
    if not source_md5:
        return json_error('Missing hash', 422)
    if not session_id:
        return json_error('Missing session_id', 422)

    try:
        return JsonResponse({
            'status': 'ok',
            'hash': source_md5,
            'session_id': session_id,
            'logs': read_session_logs(source_md5, session_id),
        })
    except Exception as exp:
        return handle_service_error(exp)
