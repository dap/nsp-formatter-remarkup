'use strict';

var cvss = require('cvss');

module.exports = function (err, data, pkgPath) {
	if (err) {
		return 'Debug output: ' + JSON.stringify(Buffer.isBuffer(data) ? data.toString() : data) + '\n' + err;
	}

	var pipeWrap = function (items) {
		return '|' + items.join('|') + '|';
	};

	var header = ['Severity', 'Name', 'Installed', 'Patched', 'Include Path', 'More Info'];

	var rows = [];
	rows.push( pipeWrap(header) );
	rows.push( pipeWrap( Array(header.length).fill('--') ) );

	data.forEach( function (finding) {
		rows.push(
			pipeWrap(
				[cvss.getRating(finding.cvss_score), finding.module, finding.version, finding.patched_versions === '<0.0.0' ? 'None' : finding.patched_versions, finding.path.join(' > '), finding.advisory]
			)
		);
	});

	return rows.join('\n');
};
