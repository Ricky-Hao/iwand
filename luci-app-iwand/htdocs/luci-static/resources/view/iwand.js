'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require poll';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

function getServiceStatus() {
	return callServiceList('iwand').then(function (res) {
		var running = false;
		try {
			running = res.iwand.instances.instance1.running;
		} catch (e) {}
		return running;
	}).catch(function () {
		return false;
	});
}

function renderStatus(running) {
	var icon = running
		? '<span style="color:#4caf50">&#x25cf;</span>'
		: '<span style="color:#f44336">&#x25cf;</span>';
	var text = running ? _('Running') : _('Stopped');
	return icon + '&nbsp;' + text;
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load('iwand'),
			getServiceStatus()
		]);
	},

	render: function (data) {
		var running = data[1];

		var m, s, o;

		m = new form.Map('iwand', _('iWAN SD-WAN'),
			_('Panabit iWAN SD-WAN client configuration.'));

		/* Status bar */
		s = m.section(form.NamedSection, 'main', 'iwand');
		s.anonymous = true;

		o = s.option(form.DummyValue, '_status', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function () { return renderStatus(running); };

		/* Enable */
		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;

		/* Connection settings */
		o = s.option(form.Value, 'interface', _('TUN Interface'));
		o.default = 'iwan0';
		o.rmempty = false;

		o = s.option(form.Value, 'server', _('Server'));
		o.datatype = 'or(ipaddr, hostname)';
		o.placeholder = '10.0.0.1';
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';
		o.default = '4567';
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.rmempty = false;

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;
		o.rmempty = false;

		o = s.option(form.Value, 'mtu', _('MTU'));
		o.datatype = 'range(46,1600)';
		o.default = '1400';

		o = s.option(form.Flag, 'encrypt', _('Encrypt'),
			_('Enable XOR encryption for data packets.'));

		/* Advanced settings */
		o = s.option(form.Value, 'pipeid', _('Pipe ID'));
		o.datatype = 'uinteger';
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.Value, 'pipeidx', _('Pipe Index'));
		o.datatype = 'uinteger';
		o.optional = true;
		o.modalonly = true;

		/* Segment routing */
		o = s.option(form.Value, 'srlinks', _('SR Links'),
			_('Comma-separated list of SR link addresses.'));
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.Value, 'srpassword', _('SR Password'));
		o.password = true;
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.ListValue, 'srencryptmode', _('SR Encrypt Mode'));
		o.value('0', _('Disabled'));
		o.value('1', _('AES-128'));
		o.value('2', _('AES-256'));
		o.default = '0';
		o.optional = true;
		o.modalonly = true;

		/* Status polling */
		poll.add(function () {
			return getServiceStatus().then(function (running) {
				var el = document.querySelector('[data-name="_status"] .td');
				if (el) el.innerHTML = renderStatus(running);
			});
		}, 5);

		return m.render();
	}
});
