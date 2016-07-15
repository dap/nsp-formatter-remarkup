'use strict';

module.exports = function (err, data, pkgPath) {
	if (err) {
		return 'Debug output: ' + JSON.stringify(Buffer.isBuffer(data) ? data.toString() : data) + '\n' + err;
	}

	var pipeWrap = function (items) {
		return '|' + items.join('|') + '|';
	};

	var rows = [];
	rows.push( pipeWrap( ['Name', 'Installed', 'Patched', 'Include Path', 'More Info'] ) );
	rows.push( pipeWrap( ['--', '--', '--', '--', '--'] ) );

	data.forEach( function (finding) {
		rows.push(
			pipeWrap(
				[finding.module, finding.version, finding.patched_versions === '<0.0.0' ? 'None' : finding.patched_versions, finding.path.join(' > '), finding.advisory]
			)
		);
	});

	return rows.join('\n');
};
