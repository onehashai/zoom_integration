// Copyright (c) 2023, OneHash Inc and contributors
// For license information, please see license.txt 

frappe.ui.form.on('ZoomSettings', {
	refresh(frm) {
		const baseUrl = new URL(window.location.href);
		baseUrl.pathname = "/";
		frm.set_value('redirect_uri', baseUrl.origin + '/api/method/zoom_integration.zoom_integration.doctype.zoom_meetings.zoom_meetings.zoom_get_access_token');
		frm.set_value('email_subscriptions_url', baseUrl.origin + '/api/method/zoom_integration.zoom_integration.doctype.zoom_meetings.zoom_meetings.webhook_validation');

		// Integrate with Zoom
		frm.add_custom_button("Integrate Zoom", function () {
			var d = new frappe.ui.Dialog({
				'fields': [
					{ 'fieldname': 'ht', 'fieldtype': 'HTML' }
				],
			});

			let zoom_marketplace_url = '<a href="https://marketplace.zoom.us">Go to Zoom Marketplace</a>';
			d.fields_dict.ht.$wrapper.html(zoom_marketplace_url);
			d.show();
		});

	}
});
