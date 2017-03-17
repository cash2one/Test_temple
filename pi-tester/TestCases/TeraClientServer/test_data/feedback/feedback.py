# -*- coding: utf-8 -*-
import logging
import base64
from handlers.base import BaseHandler
from tornado import gen
from lib.utils.io import *
from lib.utils.clean_input import *
from lib.hcfs.mgmt.auth import google_access_token_auth
from lib.teraclient.mgmt.auth import get_mgmt_auth
from lib.teraclient.auth.google_token import get_google_token

from lib.teraclient.feedback.feedback import save_feedback
from lib.teraclient.feedback.feedback import remove_feedback

from lib.teraclient.feedback.attachment import save_attachment
from lib.teraclient.feedback.attachment import get_attachment
from lib.teraclient.feedback.attachment import remove_attachment

from tasks import feedback as feedback_worker


class FeedbackHandler(BaseHandler):

    @gen.coroutine
    def post(self):
        """Send Customer Feedback

        **Example of request**

        .. sourcecode:: http

           POST /api/v1.0/feedback/ HTTP/1.1
           Host: my.tera.mobi
           Authorization: Bearer 4/QeUZvahTmFhnX...
           Accept: application/json
           Content-Type: multipart/form-data; boundary=foo_bar_baz
           X-Auth-Type: code

           --foo_bar_baz
           Content-Disposition: form-data; name="feedback"
           Content-Type: application/json; charset=UTF-8

           {
             "name": "Allen Wayne",
             "email": "allen.wayne_02108@gmail.com",
             "phone": "0937123223",
             "origin_of_issue": ["tera_phone", "tera_web"],
             "device_model": "LG Nexus 5X",
             "web_browser": {
               "name": "Google Chrome",
               "version": "52.0.2743.116",
               "os": "windows"
              },
              "category": "defect",
              "description": "我的手機在 Rest 後無法 bla bla bla.."
           }

           --foo_bar_baz
           Content-Disposition: form-data; name="attachments"; filename="system_log.zip"
           Content-Type: application/zip

           // upload file system_log.zip raw data
           /9j/4AAQSkZJRgABAQAAAQABAAD/4QBYRXhpZgAATU0AKgAAA...

           --foo_bar_baz
           Content-Disposition: form-data; name="attachments"; filename="system_init.log"
           Content-Type: text/plain

           // upload file system_log.zip raw data
           /7i/2BAQAkZJRgABAQAAAQABAAD/4QBYRXhpZgAATG0AKgAAA...
           --foo_bar_baz--

        .. seealso:: HTTP Multipart 傳送格式參見 IETF `RFC2388`_.

        .. _RFC2388: https://tools.ietf.org/html/rfc2388


        **Example of success response**:

        .. sourcecode:: http

           HTTP/1.1 200 OK
           Content-Type: application/json
           Cache-Control: no-cache, no-store, must-revalidate
           Pragma: no-cache
           Expires: 0


        **Example of error response**:

        .. sourcecode:: http

           HTTP/1.1 400 Bad request
           Content-Type: application/json
           Cache-Control: no-cache, no-store, must-revalidate
           Pragma: no-cache
           Expires: 0

           {
             "message": "missing or invalid token format"
           }

        :statuscode 200: success
        :statuscode 400: invalid input, see message.
        :statuscode 403: session expired, see message.
        :statuscode 500: internal server error, see message.

        """
        try:
            import pdb
            db = self.db
            session_live_time = self.settings['session_live_time']
            client_id = self.settings['google_oauth']['key']
            client_secret = self.settings['google_oauth']['secret']

            session_id = yield get_request_session_id(self)
            session_id = yield clean_session_id(session_id)

            auth_type = yield get_request_auth_type(self)

            if auth_type == 'code':
                mgmt_auth = yield google_access_token_auth(
                    self.settings['mgmt_url'], code=session_id
                )
            else:

                google_token = yield get_google_token(
                    db, session_id, client_id, client_secret, session_live_time
                )

                mgmt_auth = yield get_mgmt_auth(
                    db, self.settings['mgmt_url'], google_token
                )

            user_id = mgmt_auth.get('user_id')
            username = mgmt_auth.get('username')
            token = mgmt_auth.get('token')
            pdb.set_trace()
            feedback = self.get_argument('feedback')
            feedback = yield clean_feedback(feedback)
            pdb.set_trace()
            attachments = []
            for attachment in self.request.files.get('attachments'):
                attachment_id = yield save_attachment(db, attachment=attachment)
                attachments.append(attachment_id)
            pdb.set_trace()
            feedback['attachments'] = attachments
            feedback_id = yield save_feedback(db, feedback=feedback)

            feedback_worker.send.apply_async([feedback_id])

            json_response(self, feedback, 'success')

        except Exception as e:
            logging.error('[exception] api/feedback/FeedbackHandler/post: %s' % str(e))
            code = yield detect_status_code(str(e))
            json_response(self, str(e), 'error', code)
