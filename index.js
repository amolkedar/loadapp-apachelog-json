'use strict';
console.log('Loading function');

/* Apache Log format parser */
const parser = /^([\d.]+) (\S+) (\S+) \[([\w:/]+)(\s[\+\-]\d{4}){0,1}\] "(.+?)" (\d{3}) (\d+) (\S+) "(.+?)"/;

exports.handler = (event, context, callback) => {
    let success = 0; // Number of valid entries found
    let failure = 0; // Number of invalid entries found

    /* Process the list of records and transform them */
    const output = event.records.map((record) => {
        const entry = (Buffer.from(record.data, 'base64')).toString('utf8');
        const match = parser.exec(entry);
        if (match) {
            /* Prepare JSON version from Apache log data */
            const safeStringToInt = (strVal) => {
                if (isNaN(Number(strVal))) {
                    return strVal;
                } else {
                    return Number(strVal);
                }
            };
            const formatDate = (strVal) => strVal.replace(/\//g, ' ').replace(':', ' ');

            const result = {
                host: match[1],
                ident: match[2],
                authuser: match[3],
                response: safeStringToInt(match[7]),
                bytes: safeStringToInt(match[8]),
                browser: match[10]         
            };

            if (match[6] && match[6].split(' ').length > 1) {
                result.verb = match[6].split(' ')[0];
                result.request = match[6].split(' ')[1];
            }
            
            result.url = match[9].split('/')[2];
            
            let isoTs = match[4];
            try {
                isoTs = new Date(formatDate(isoTs)).toISOString();
            } catch (err) {
                console.log('Parsing the timestamp to date failed.');
            }
            result['@timestamp'] = isoTs;

            if (match[5]) {
                const timezone = match[5].trim();
                result.timezone = timezone;
                try {
                    const ts = formatDate(match[4]);
                    const combinedTs = `${ts} ${timezone}`;
                    result['@timestamp_utc'] = new Date(combinedTs).toISOString();
                } catch (err) {
                    console.log('Calculating UTC time failed.');
                }
            }

            console.log('HOST IP is :' + JSON.stringify(result.host));            
            console.log('BIG data is:' + JSON.stringify(result));
            const payload = (Buffer.from(JSON.stringify(result), 'utf8')).toString('base64');
            success++;
            return {
                recordId: record.recordId,
                result: 'Ok',
                data: payload,
            };
        } else {
            /* Failed event, notify the error and leave the record intact */
            failure++;
            return {
                recordId: record.recordId,
                result: 'ProcessingFailed',
                data: record.data,
            };
        }
    });
    console.log(`Processing completed.  Successful records ${success}, Failed records ${failure}.`);
    callback(null, { records: output });
};
