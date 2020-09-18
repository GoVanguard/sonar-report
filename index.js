#!/usr/bin/env node

const argv = require("minimist")(process.argv.slice(2));
const request = require("sync-request");
const ejs = require("ejs");

if (argv.help) {
  console.log(`SYNOPSIS
    sonar-report [OPTION]...

USAGE
    sonar-report --project=MyProject --application=MyApp --release=v1.0.0 --sonarurl=http://my.sonar.example.com --sonarcomponent=myapp:1.0.0 --sinceleakperiod=true > /tmp/sonar-report

DESCRIPTION
    Generate a vulnerability report from a SonarQube instance.

    --project
        name of the project, displayed in the header of the generated report

    --application
        name of the application, displayed in the header of the generated report

    --release
        name of the release, displayed in the header of the generated report

    --branch
        Branch in Sonarqube that we want to get the hotspots for

    --sonarurl
        base URL of the SonarQube instance to query from

    --sonarcomponent
        id of the component to query from

    --sonarusername
        auth username

    --sonarpassword
        auth password

    --sonartoken
        auth token

    --sonarorganization
        name of the sonarcloud.io organization

    --sinceleakperiod
        flag to indicate if the reporting should be done since the last sonarqube leak period (delta analysis). Default is false.

    --allbugs
        flag to indicate if the report should contain all bugs, not only vulnerabilities. Default is false

    --fixMissingRule
        Extract rules without filtering on type (even if allbugs=false). Not useful if allbugs=true. Default is false

    --noSecurityHotspot
        Set this flag for old versions of sonarQube without security hotspots (<7.3?). Default is false

    --help
        display this help message`);
  process.exit();
}

var vulnerabilityProbability = new Map();
vulnerabilityProbability.set('LOW', 0);
vulnerabilityProbability.set('MEDIUM', 1);
vulnerabilityProbability.set('HIGH', 2);

const data = {
  date: new Date().toDateString(),
  projectName: argv.project,
  applicationName: argv.application,
  releaseName: argv.release,
  branch: argv.branch,
  sinceLeakPeriod: (argv.sinceleakperiod == 'true'),
  previousPeriod: '',
  allBugs: (argv.allbugs == 'true'),
  fixMissingRule: (argv.fixMissingRule == 'true'),
  noSecurityHotspot: (argv.noSecurityHotspot == 'true'),
  // sonar URL without trailing /
  sonarBaseURL: argv.sonarurl.replace(/\/$/, ""),
  sonarOrganization: argv.sonarorganization,
  rules: [],
  hotspots: []
};

const leakPeriodFilter = data.sinceLeakPeriod ? '&sinceLeakPeriod=true' : '';
data.deltaAnalysis = data.sinceLeakPeriod ? 'Yes' : 'No';
const sonarBaseURL = data.sonarBaseURL;
const sonarComponent = argv.sonarcomponent;
const withOrganization = data.sonarOrganization ? `&organization=${data.sonarOrganization}` : '';
const options = { headers: {} };

let DEFAULT_FILTER="";
let OPEN_STATUSES="";
// Default filter gets only vulnerabilities
// For newer versions of sonar, rules and hotspots may be of type VULNERABILITY or SECURITY_HOTSPOT
DEFAULT_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
// the security hotspot adds TO_REVIEW,IN_REVIEW
OPEN_STATUSES="TO_REVIEW,IN_REVIEW"

// filters for getting rules and hotspots
let filterRule = DEFAULT_FILTER;
let filterIssue = DEFAULT_FILTER;

if(data.allBugs){
  filterRule = "";
  filterIssue = "";
}

if(data.branch){
  filterIssue=filterIssue + "&branch=" + data.branch
}

if(data.fixMissingRule){
  filterRule = "";
}

{
  const username = argv.sonarusername;
  const password = argv.sonarpassword;
  const token = argv.sonartoken;
  if (username && password) {
    // Form authentication with username/password
    const res = request(
      "POST",
      `${sonarBaseURL}/api/authentication/login`, {
        body: `login=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    options.headers["Cookie"] = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]).join('; ');
  } else if (token) {
    // Basic authentication with user token
    options.headers["Authorization"] = "Basic " + Buffer.from(token + ":").toString("base64");
  }
}

if (data.sinceLeakPeriod) {
  const res = request(
    "GET",
    `${sonarBaseURL}/api/settings/values?keys=sonar.leak.period`,
    options
  );
  const json = JSON.parse(res.getBody());
  data.previousPeriod = json.settings[0].value;
}

{
  const pageSize = 500;
  let page = 1;
  let nbResults;

  do {
    const res = request(
      "GET",
      `${sonarBaseURL}/api/rules/search?activation=true&ps=${pageSize}&p=${page}${filterRule}`,
      options
    );
    page++;
    const json = JSON.parse(res.getBody());
    nbResults = json.rules.length;
    data.rules = data.rules.concat(json.rules.map(rule => ({
      key: rule.key,
      htmlDesc: rule.htmlDesc,
      name: rule.name,
      vulnerabilityProbability: rule.vulnerabilityProbability
    })));
  } while (nbResults === pageSize);

}

{
  const pageSize = 500;
  let page = 1;
  let nbResults;
  do {
    /** Get all statuses except "REVIEWED". 
     * Actions in sonarQube vs status in security hotspot (sonar >= 7): 
     * - resolve as reviewed
     *    "resolution": "FIXED"
     *    "status": "REVIEWED"
     * - open as vulnerability
     *    "status": "OPEN"
     * - set as in review
     *    "status": "IN_REVIEW"
     */
    let query = `${sonarBaseURL}/api/hotspots/search?projectKey=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=${OPEN_STATUSES}&onlyMine=false&sinceLeakPeriod=false`
    /*console.log(query);*/
    const res = request(
      "GET",
      query,
      options
    );
    page++;
    const json = JSON.parse(res.getBody());
    nbResults = json.hotspots.length;
    /*console.log("Results");
    console.log(nbResults);
    console.log(json);*/
    data.hotspots = data.hotspots.concat(json.hotspots.map(hotspot => {
      return {
        // For security hotspots, the vulnerabilities show without a vulnerabilityProbability before they are confirmed
        // In this case, get the vulnerabilityProbability from the rule
        vulnerabilityProbability: hotspot.vulnerabilityProbability,
        status: hotspot.status,
        // Take only filename with path, without project name
        component: hotspot.component.split(':').pop(),
        line: hotspot.line,
        description: hotspot.message, 
        message: hotspot.message,
        key: hotspot.key
      };
    }));
  } while (nbResults === pageSize);

  data.hotspots.sort(function (a, b) {
    return vulnerabilityProbability.get(b.vulnerabilityProbability) - vulnerabilityProbability.get(a.vulnerabilityProbability);
  });

  data.summary = {
    high: data.hotspots.filter(hotspot => hotspot.vulnerabilityProbability === "HIGH").length,
    medium: data.hotspots.filter(hotspot => hotspot.vulnerabilityProbability === "MEDIUM").length,
    low: data.hotspots.filter(hotspot => hotspot.vulnerabilityProbability === "LOW").length,
  };
}

ejs.renderFile(`${__dirname}/index.ejs`, data, {}, (err, str) => {
  console.log(str);
});
