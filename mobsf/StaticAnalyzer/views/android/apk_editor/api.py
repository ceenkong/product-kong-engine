import logging

from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.MobSF.views.helpers import request_method
from mobsf.StaticAnalyzer.views.android.apk_editor.frida import (
    inject_frida_gadget,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.obfuscation import (
    obfuscate_session,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    discard_session,
    get_editor_status,
    start_session,
)


logger = logging.getLogger(__name__)
GENERIC_ERROR = 'APK editor operation failed'


def missing_hash_response():
    return make_api_response({'error': 'Missing hash'}, 422)


def missing_session_response():
    return make_api_response({'error': 'Missing session_id'}, 422)


def handle_service_error(exp):
    if isinstance(exp, ValueError):
        return make_api_response({'error': str(exp)}, 400)
    logger.exception('APK editor operation failed')
    return make_api_response({'error': GENERIC_ERROR}, 500)


def request_value(request, name):
    return request.GET.get(name) or request.POST.get(name)


@request_method(['POST'])
@csrf_exempt
def api_start(request):
    source_md5 = request.POST.get('hash')
    if not source_md5:
        return missing_hash_response()

    try:
        return make_api_response(start_session(source_md5), 200)
    except Exception as exp:
        return handle_service_error(exp)


@request_method(['GET', 'POST'])
@csrf_exempt
def api_status(request):
    source_md5 = request_value(request, 'hash')
    session_id = request_value(request, 'session_id')
    if not source_md5:
        return missing_hash_response()

    try:
        return make_api_response(
            get_editor_status(source_md5, session_id),
            200,
        )
    except Exception as exp:
        return handle_service_error(exp)


@request_method(['POST'])
@csrf_exempt
def api_discard(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return missing_hash_response()
    if not session_id:
        return missing_session_response()

    try:
        return make_api_response(discard_session(source_md5, session_id), 200)
    except Exception as exp:
        return handle_service_error(exp)


@request_method(['POST'])
@csrf_exempt
def api_frida_gadget(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return missing_hash_response()
    if not session_id:
        return missing_session_response()

    try:
        abis = request.POST.getlist('abis') or None
        return make_api_response(
            inject_frida_gadget(source_md5, session_id, abis),
            200,
        )
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


@request_method(['POST'])
@csrf_exempt
def api_obfuscate(request):
    source_md5 = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_md5:
        return missing_hash_response()
    if not session_id:
        return missing_session_response()

    try:
        return make_api_response(
            obfuscate_session(
                source_md5,
                session_id,
                obfuscation_options(request),
            ),
            200,
        )
    except Exception as exp:
        return handle_service_error(exp)
