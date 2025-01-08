from frappe.model.document import Document
import frappe
import frappe.utils
import hashlib
import hmac
import json
import requests
import base64
from datetime import datetime
from werkzeug.wrappers import Response
from frappe.integrations.utils import make_post_request

@frappe.whitelist(allow_guest=True)
def delete_zoom_meeting(self):
	url = 'https://api.zoom.us/v2/meetings/'+self.meeting_id
	requests.request("DELETE", url, headers=get_header())

@frappe.whitelist(allow_guest=True)
def update_zoom_meeting(self):
	url = 'https://api.zoom.us/v2/meetings/'+self.meeting_id

	meeting={
	"duration": self.duration,
	"password": self.password,
	"timezone": self.timezone,
	"agenda": self.description,
	"topic": self.topic,
	"start_time":format_onehash_to_zoom_date(self.starttime),
	"settings": {
		"host_video": self.host_video,
		"participant_video": self.participation_video,
		"join_before_host": self.join_before_host,
		"mute_upon_entry": self.mute_upon_entry,
		"use_pmi":self.use_pmi
		}
	}
	requests.request("PATCH", url, headers=get_header(),data=json.dumps(meeting))
	self.invitation_message=get_meeting_invitation(self.meeting_id)

	if self.add_registrants:
		create_meeting_registrant(self)

@frappe.whitelist(allow_guest=True)
def create_meeting_registrant(self):
	url = 'https://api.zoom.us/v2/meetings/'+self.meeting_id+"/registrants"

	if (not self.user_groupss) or self.user_groupss=='':
		frappe.log_error("User Group not present","User Group not present")
	else:
		user_group=frappe.get_doc("User Group",self.user_groupss)
		for usermember in user_group.user_group_members:
			user = frappe.get_doc('User', usermember.user)
			registrant={
			"first_name": user.first_name,
			"last_name": user.last_name,
			"email": user.email
			}
			requests.request("POST", url, headers=get_header(),data=json.dumps(registrant))
			notify_meeting_registrant(self.invitation_message,user.first_name,user.email)
		frappe.msgprint( """Notification send successfully to Participants""")

	recipients=[]
	for user in self.zoom_emails:
		registrant={
		"first_name": user.first_name,
		"last_name": user.last_name,
		"email": user.email
		}
		recipients.append(registrant.get("email"))
		requests.request("POST", url, headers=get_header(),data=json.dumps(registrant))

	if len(recipients)>0:
		email_meeting_registrant(recipients,self.invitation_message,"alerts@onehash.ai","Zoom Meeting Invitation")

@frappe.whitelist(allow_guest=True)
def email_meeting_registrant(recipients,invitation_message,sender,subject):
	try:
		frappe.sendmail(recipients=recipients, subject=subject, message=invitation_message, sender=sender)
		frappe.msgprint( """Email send successfully to Participants""")
	except:
		frappe.log_error("Error in sending mail","Send email error")

@frappe.whitelist(allow_guest=True)
def notify_meeting_registrant(invitation_message,username,email):
	frappe.get_doc({
		'doctype': 'Notification Log',
		'subject': f'Meeting Invitation',
		'email_content':f" {invitation_message}",
		'type': 'Alert',
		'document_type': 'Employee',
		'document_name': username,
		'for_user': email
	}).insert(ignore_permissions=True)

@frappe.whitelist(allow_guest=True)
def get_meeting_invitation(meeting_id):
	url = "https://api.zoom.us/v2/meetings/" +str(meeting_id)+"/invitation"
	try:
		response = requests.get(url, headers=get_header())
		response.raise_for_status()
		return response.json().get('invitation', '')
	except requests.exceptions.RequestException as e:
		return None

@frappe.whitelist(allow_guest=True)
def create_zoom_meeting():
	url = 'https://api.zoom.us/v2/users/me/meetings'
	request=frappe.form_dict
	meeting={
	"agenda":str(request['agenda']) +"          Created by: "+str(frappe.session.data.user),
	"topic": request['topic'],
	}
	try:
		make_post_request(url,headers=get_header(),data=json.dumps(meeting))
	except:
		frappe.msgprint("Access Token Expired or too many meeting request created, SignIn again")

@frappe.whitelist(allow_guest=True)
def get_header():
	zoom_settings=frappe.get_doc("Zoom Settings")
	authentication_token='Bearer '+zoom_settings.authentication_token

	headers = {
		'Content-Type':  'application/json',
		'Authorization': authentication_token
	}
	return headers

@frappe.whitelist(allow_guest=True)
def get_a_zoom_meeting(meeting_id):
	url = "https://api.zoom.us/v2/meetings/" +str(meeting_id)
	try:
		response = requests.get(url, headers=get_header())
		response.raise_for_status()
		return response.json()
	except requests.exceptions.RequestException as e:
		return None

@frappe.whitelist(allow_guest=True)
def format_zoom_to_onehash_date(start_time):
	dt = datetime.strptime(start_time, '%Y-%m-%dT%H:%M:%SZ')
	start_time_formatted = dt.strftime('%Y-%m-%d %H:%M:%S.%f')
	return start_time_formatted

@frappe.whitelist(allow_guest=True)
def format_onehash_to_zoom_date(start_time):
	dt = datetime.strptime(start_time,'%Y-%m-%d %H:%M:%S')
	start_time_formatted = dt.strftime('%Y-%m-%dT%H:%M:%S')
	return start_time_formatted

@frappe.whitelist(allow_guest=True)
def webhook_validation():
	secret_token=frappe.get_doc("Zoom Settings").secret_token
	request=frappe.form_dict

	if request['event']=="endpoint.url_validation":
		plain_token=request['payload']['plainToken']
		response = {
			"plainToken": plain_token,
			"encryptedToken": get_encrypted_password(plain_token,secret_token)
		}
		return  Response(json.dumps(response), mimetype='application/json')

	elif request['event']=='meeting.created':
		request=frappe.form_dict['payload']['object']
		request=get_a_zoom_meeting(request['id'])

		zoom_meeting=frappe.get_doc({
			'doctype':'Zoom Meetings',
			'password':request['password'],
			'join_url':request['join_url'],
			'meeting_id':request['id'],
			'starttime': format_zoom_to_onehash_date(request['start_time']),
			'description':request['agenda'],
			'duration':request['duration'],
			'host_video':request['settings']['host_video'],
			'mute_upon_entry':request['settings']['mute_upon_entry'],
			'participation_video':request['settings']['participant_video'],
			'timezone':request['timezone'],
			'topic':request['topic'],
			'uuid':request['uuid'],
			'join_before_host':request['settings']['join_before_host'],
			"use_pmi":request['settings']['use_pmi'],
			'invitation_message':get_meeting_invitation(request['id']),
			'host_email':request['host_email'],
			'createdat':format_zoom_to_onehash_date(request['created_at']),
			'start_url':request['start_url'],
			'host_email':(request['agenda'][(request["agenda"].index("Created by: ") + len("Created By: ")):])
		})
		zoom_meeting.db_insert()

	elif request['event']=='meeting.updated':
		request=get_a_zoom_meeting(request['payload']['object']['id'])

		zoom_meeting = frappe.get_doc('Zoom Meetings', request['id'])
		zoom_meeting.password = request['password']
		zoom_meeting.join_url = request['join_url']
		zoom_meeting.starttime = format_zoom_to_onehash_date(request['start_time'])
		zoom_meeting.description = request['agenda']
		zoom_meeting.duration = request['duration']
		zoom_meeting.host_video = request['settings']['host_video']
		zoom_meeting.mute_upon_entry = request['settings']['mute_upon_entry']
		zoom_meeting.participation_video = request['settings']['participant_video']
		zoom_meeting.timezone = request['timezone']
		zoom_meeting.topic = request['topic']
		zoom_meeting.uuid = request['uuid']
		zoom_meeting.join_before_host = request['settings']['join_before_host']
		zoom_meeting.use_pmi = request['settings']['use_pmi']
		zoom_meeting.invitation_message = get_meeting_invitation(request['id'])
		zoom_meeting.host_email = request['host_email']
		zoom_meeting.createdat = format_zoom_to_onehash_date(request['created_at'])
		zoom_meeting.start_url = request['start_url']
		zoom_meeting.db_update()

	elif request['event']=='meeting.deleted':
		frappe.db.delete('Zoom Meetings',request['payload']['object']['id'])

def get_encrypted_password(plain_text, secret_key):
	return hmac.new(secret_key.encode('utf-8'), plain_text.encode('utf-8'), hashlib.sha256).hexdigest()

@frappe.whitelist(allow_guest=True)
def zoom_get_access_token():
	zoom_settings=frappe.get_doc("Zoom Settings")
	client_id=zoom_settings.client_id
	client_secret=zoom_settings.client_secret
	redirect_uri=zoom_settings.redirect_uri

	code=frappe.form_dict['code']

	url='https://zoom.us/oauth/token?grant_type=authorization_code&redirect_uri='+redirect_uri+'&code='+code

	auth_string = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
	headers={

		"Authorization": f'Basic {auth_string}',
		"Content-Type": "application/x-www-form-urlencoded"
	}
	response=make_post_request(url,headers=headers)
	frappe.response["type"] = "redirect"
	frappe.response["location"] = '/app/zoom-meetings?loggedin=true'+'&authentication_token='+response['access_token']

class ZoomMeetings(Document):
	def after_delete(self):
		delete_zoom_meeting(self)

	def before_save(self):
		update_zoom_meeting(self)
	pass