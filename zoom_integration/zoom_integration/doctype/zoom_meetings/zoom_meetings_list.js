
/* List view in Zoom Meeting */
frappe.listview_settings['Zoom Meetings'] = {
	refresh: function (listview) {


		/* Parameters in Url, converted to key value pairs. */
		const urlParams = new URLSearchParams(window.location.search);
		if (urlParams.get('loggedin') === 'true') {

			//Saving access token in zoom settings
			let authentication_token = urlParams.get('authentication_token');
			frappe.db.set_value('ZoomSettings', 'ZoomSettings', 'authentication_token', authentication_token);

			// Popup to show user is logged in
			let d = new frappe.ui.Dialog({
				title: 'You are LoggedIn to Zoom',
				fields: [
				],
				primary_action_label: 'Close',
				primary_action(values) {

					d.hide();
					const baseUrl = new URL(window.location.href);
					baseUrl.pathname = "/";
					window.location.href = baseUrl.origin+'/app/zoom-meetings',"ZoomSettings";
				}
			});
			d.show();
		}


		//Disable Add Meeting Button
		let addButton = document.querySelector('.btn.btn-primary.btn-sm.primary-action');
		addButton.disabled = true;

		/* SignIn Button to Zoom */
		listview.page.add_inner_button("Sign In with Zoom", async function () {

			//SignIn Url
			let client_id = await frappe.db.get_single_value('ZoomSettings', 'client_id');
			let redirect_uri = await frappe.db.get_single_value('ZoomSettings', 'redirect_uri');
			window.location.href = 'https://zoom.us/oauth/authorize?response_type=code&client_id=' + client_id + '&redirect_uri=' + redirect_uri;

		});

		// Create Zoom Meeting
		listview.page.add_inner_button("Create Zoom Meeting", function () {

			let d = new frappe.ui.Dialog({
				title: 'Create a Meeting',
				fields: [
					{
						label: 'Topic',
						fieldname: 'topic',
						fieldtype: 'Data',
						reqd: 1
					},
					{
						label: 'Description',
						fieldname: 'agenda',
						fieldtype: 'Small Text',
						reqd: 1
					}
				],
				primary_action_label: 'Submit',
				primary_action(values) {
					const baseUrl = new URL(window.location.href);
					baseUrl.pathname = "/";
					frappe.call({
						args: {
							'agenda': values.agenda,
							'topic': values.topic
						},
						callback: (r) => {
							console.log(r)
						},
						url: baseUrl.origin+'/api/method/zoom_integration.zoom_integration.doctype.zoom_meetings.zoom_meetings.create_zoom_meeting',
						success: function (response) {
						}
					});
					d.hide();
				}
			});
			d.show();
		});
	},
	button: {
		show: function (doc) {
			return true;
		},
		get_label: function () {
			return __('View');
		},
		get_description: function (doc) {
			return __('Print {0}', [doc.name])
		},
		action: function (doc) {
			console.log(window);
		}
	}
}
