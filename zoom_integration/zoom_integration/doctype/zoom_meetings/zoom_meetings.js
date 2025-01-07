// Copyright (c) 2023, OneHash Inc and contributors
// For license information, please see license.txt

frappe.ui.form.on('Zoom Meetings', {
	after_save: function (frm) {
		frappe.show_alert('Zoom meeting updated', 5);
	}
});
