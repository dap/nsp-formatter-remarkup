'use strict';

var cvss = require('cvss');

module.exports = function (err, data, pkgPath) {
	if (err) {
		return err;
	}

	var pipeWrap = function (items) {
		return '|' + items.join('|') + '|';
	};

	var header = [
		'Severity',
		'Title',
		'Module',
		'Installed',
		'Patched',
		'Include Path',
		'More Info'
	];

	var rows = [];
	rows.push( pipeWrap(header) );
	rows.push( pipeWrap( Array(header.length).fill('--') ) );

	data.forEach( function (finding) {
		var advisory_number
			= finding.advisory.substr(finding.advisory.lastIndexOf('/'));

		var patched_versions
			= finding.patched_versions === '<0.0.0'
				? 'None'
				: finding.patched_versions.replace(/\|\|/g, 'OR');

		rows.push(
			pipeWrap([
				cvss.getRating(finding.cvss_score),
				finding.title,
				finding.module,
				finding.version,
				patched_versions,
				'{nav ' + finding.path.join(' > ') + '}',
				'[[' + finding.advisory + '|nspa' + advisory_number + ']]'
			])
		);
	});

	return rows.join('\n');
};
