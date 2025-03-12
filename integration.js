'use strict';

const request = require('postman-request');
const config = require('./config/config');
const get = require('lodash.get');
const groupBy = require('lodash.groupby');
const async = require('async');
const fs = require('fs');
const { Readable } = require('stream');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 5;
const MAX_ACTORS_IN_SUMMARY = 5;
const CONSECUTIVE_DOTS_REGEX = /\.\./;

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _convertPolarityTypeToAnalyst1Type(entityType) {
  switch (entityType) {
    case 'IPv4':
      return 'ip';
    case 'IPv6':
      return 'ipv6';
    case 'hash':
      return 'file';
    case 'email':
      return 'email';
    case 'domain':
      return 'domain';
  }
}

function getIndicatorBulkMatchRequestOptions(entityType, searchString, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/batchCheck`,
    qs: {
      values: searchString
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

function doCveLookups(cveEntities, options, cb) {
  const tasks = [];

  cveEntities.forEach((cve) => {
    tasks.push(lookupCve.bind(this, cve, options));
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, cb);
}

/**
 * Returns a resultObject for a single CVE lookup
 * @param cveEntity
 * @param options
 * @param cb
 */
function lookupCve(cveEntity, options, cb) {
  const requestOptions = getCveSearchOptions(cveEntity, options);
  Logger.trace({ requestOptions }, 'CVE Lookup Request Options');
  request(requestOptions, (err, response, body) => {
    const result = handleRestError(err, response, body);
    Logger.trace({ result }, 'CVE Search Result');
    if (result.error) {
      return cb(result);
    }
    if (result.body && result.body.totalResults === 0) {
      return cb(null, {
        entity: cveEntity,
        data: null
      });
    }

    cb(null, {
      entity: cveEntity,
      data: {
        summary: _getCveSummaryTags(result.body),
        details: _getDetails(cveEntity, result.body)
      }
    });
  });
}

function getCveSearchOptions(cveEntity, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/actor`,
    qs: {
      cve: cveEntity.value,
      limit: 1
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

function isValidExtendedEmail(entity) {
  if (entity.value.startsWith('.')) {
    return false;
  }

  const tokens = entity.value.split('@');
  if (tokens.length > 0 && tokens[0].endsWith('.')) {
    return false;
  }

  if (tokens.length > 0 && CONSECUTIVE_DOTS_REGEX.test(tokens[0])) {
    return false;
  }

  return true;
}

function getIndicatorById(indicatorId, options, cb) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  const requestOptions = {
    method: 'GET',
    uri: `${url}api/1_0/indicator/${indicatorId}`,
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };

  request(requestOptions, (err, response, body) => {
    let processedResult = handleRestError(err, response, body);
    Logger.trace({ processedResult }, 'Processed Result');
    if (processedResult.error) {
      cb(processedResult);
      return;
    }

    cb(null, processedResult.body);
  });
}

function doIndicatorLookups(entityType, entityValues, options, cb) {
  const lookupResults = [];

  const entityLookup = entityValues.reduce((entityMap, entity) => {
    entityMap.set(entity.value.toLowerCase(), entity);
    return entityMap;
  }, new Map());
  const searchString = entityValues.map((entity) => entity.value).join(',');
  const requestOptions = getIndicatorBulkMatchRequestOptions(entityType, searchString, options);
  Logger.trace({ requestOptions }, 'Bulk Lookup Request Options');
  request(requestOptions, (err, response, body) => {
    const result = handleRestError(err, response, body);
    if (result.error) {
      return cb(result);
    }
    if (result.body && Array.isArray(result.body.results)) {
      async.eachLimit(
        result.body.results,
        3,
        (indicatorResult, done) => {
          if (get(indicatorResult, 'entity.key', '') === 'INDICATOR') {
            const entityValue = get(indicatorResult, 'searchedValue', '').toLowerCase();
            const entity = entityLookup.get(entityValue);

            // Makes it easy to see what entities had misses
            entityLookup.delete(entityValue);
            if (!entity) {
              Logger.error({ indicatorResult }, 'Indicator Result is missing `value.searchedValue`');
              return;
            }
            getIndicatorById(indicatorResult.id, options, (err, indicatorDetails) => {
              if (err) {
                return done(err);
              }

              if (options.verifiedOnly && indicatorDetails.verified === false) {
                lookupResults.push({
                  entity,
                  data: null
                });
              } else {
                lookupResults.push({
                  entity,
                  data: {
                    summary: _getSummaryTags(indicatorDetails, options),
                    details: _getDetails(entity, indicatorDetails, options)
                  }
                });
              }

              done();
            });
          } else {
            // This is a bulkCheck results that is not an indicator
            // so we don't do anything with it
            done();
          }
        },
        (err) => {
          if (err) {
            Logger.error({ err }, 'Error in doLookup');
            return cb(err);
          }

          // Any entities left in our lookup map did not have a hit so we create a miss for them
          Array.from(entityLookup.values()).forEach((entity) => {
            lookupResults.push({
              entity,
              data: null
            });
          });

          cb(null, lookupResults);
        }
      );
    }
  });
}

function doLookup(entities, options, cb) {
  let lookupResults = [];

  const entitiesFiltered = entities.reduce((accum, entity) => {
    // Warning: we are mutating the underlying entity types here so that the custom extended email type is
    // treated as an email.  We also filter out invalid emails here
    if (entity.type === 'custom') {
      entity.type = 'email';
      if (isValidExtendedEmail(entity)) {
        accum.push(entity);
      }
    } else {
      accum.push(entity);
    }
    return accum;
  }, []);

  Logger.trace({ entitiesFiltered, options }, 'doLookup');

  const groupedEntities = groupBy(entitiesFiltered, 'type');

  async.eachOf(
    groupedEntities,
    (entityValuesForType, entityType, done) => {
      if (entityType === 'cve') {
        doCveLookups(entityValuesForType, options, (err, results) => {
          if (err) {
            return done(err);
          }
          lookupResults = lookupResults.concat(results);
          done();
        });
      } else {
        doIndicatorLookups(entityType, entityValuesForType, options, (err, results) => {
          if (err) {
            return done(err);
          }
          lookupResults = lookupResults.concat(results);
          done();
        });
      }
    },
    (err) => {
      Logger.trace({ lookupResults }, 'lookupResults');
      if (err) {
        Logger.error(err, 'Error in doLookup');
      }
      cb(err, lookupResults);
    }
  );
}


function parseErrorToReadableJSON(error) {
  return JSON.parse(JSON.stringify(error, Object.getOwnPropertyNames(error)));
}

function _getDetails(entity, searchResult, options) {
  Logger.trace({ searchResult }, '_getDetails');

  if (entity.type === 'cve') {
    let actors = searchResult.results.map((actor) => {
      return {
        name: get(actor, 'title.name', 'No Name'),
        id: get(actor, 'id', null)
      };
    });
    return { actors, results: [] };
  }

  let result;
  if (Array.isArray(searchResult)) {
    result = searchResult.map((result) => {
      if (Array.isArray(result.reportedDates)) {
        result._firstReportedDate = result.reportedDates[0];
        result._lastReportedDate = result.reportedDates[result.reportedDates.length - 1];
      }
      if (Array.isArray(result.activityDates)) {
        result._firstActivityDate = result.activityDates[0];
        result._lastActivityDate = result.activityDates[result.activityDates.length - 1];
      }
      return result;
    });
  } else {
    if (Array.isArray(searchResult.reportedDates)) {
      searchResult._firstReportedDate = searchResult.reportedDates[0];
      searchResult._lastReportedDate = searchResult.reportedDates[searchResult.reportedDates.length - 1];
    }
    if (Array.isArray(searchResult.activityDates)) {
      searchResult._firstActivityDate = searchResult.activityDates[0];
      searchResult._lastActivityDate = searchResult.activityDates[searchResult.activityDates.length - 1];
    }
    result = [searchResult];
  }

  return { results: result };
}

function _getCveSummaryTags(body) {
  const tags = [];
  if (Array.isArray(body.results)) {
    for (let i = 0; i < body.results.length && i < MAX_ACTORS_IN_SUMMARY; i++) {
      const actor = body.results[i];
      const actorName = get(actor, 'title.name');
      if (actorName) {
        tags.push(`Actor: ${actorName}`);
      }
    }
  }

  if (tags.length < body.results.length) {
    tags.push(`+${body.results.length - tags.length} more actors`);
  }

  return tags;
}

function _getSummaryTags(body, options) {
  const tags = [];

  if (typeof body.active !== 'undefined') {
    if (body.active) {
      tags.push(`Active`);
    } else {
      tags.push(`Not Active`);
    }
  }

  if (body.tlp !== 'undetermined') {
    tags.push(`TLP: ${body.tlp}`);
  }

  tags.push(`# Reports: ${body.reportCount}`);

  if (Array.isArray(body.actors)) {
    body.actors.slice(0, 3).forEach((actor) => {
      tags.push(`Actor: ${actor.name}`);
    });
    if (body.actors.length > 5) {
      tags.push(`+${body.actors.length - 5} actors`);
    }
  }

  return tags;
}

function getActorById(entity, actor, options, cb) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  const requestOptions = {
    method: 'GET',
    uri: `${url}api/1_0/actor/${actor.id}`,
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };

  Logger.trace({ requestOptions }, 'getActorById');
  requestWithDefaults(requestOptions, (error, result, body) => {
    let processedResult = handleRestError(error, result, body);
    Logger.trace({ processedResult }, 'Processed Result');
    if (processedResult.error) {
      cb(processedResult);
      return;
    }

    cb(null, processedResult);
  });
}

function onDetails(lookupResult, options, cb) {
  if (lookupResult.entity.type !== 'cve') {
    return cb(null, lookupResult.data);
  }

  const actors = [];

  async.each(
    lookupResult.data.details.actors,
    (actor, done) => {
      getActorById(lookupResult.entity, actor, options, (err, result) => {
        if (err) {
          return done(err);
        }
        actors.push(result.body);
        done();
      });
    },
    (err) => {
      if (err) {
        return cb(err);
      }
      lookupResult.data.details.results = actors;
      Logger.trace({ 'block.data.details.results': lookupResult.data.details.results }, 'onDetails Result');
      cb(err, lookupResult.data);
    }
  );
}

function checkUploadStatus(uuid, options, cb) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;
  const requestOptions = {
    uri: `${url}api/1_0/evidence/uploadStatus/${uuid}`,
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
  request(requestOptions, (err, response, body) => {
    if (err) {
      return cb(err);
    }

    if (response.statusCode === 200) {
      Logger.trace({ uuid, body }, 'Check Upload Status Response');
      if (body.id === null) {
        cb(null, {
          isComplete: false
        });
      } else {
        cb(null, {
          isComplete: true,
          evidenceId: body.id
        });
      }
    } else {
      cb({
        detail: `Unexpected status code ${response.statusCode} received`,
        body
      });
    }
  });
}

function addEvidence(indicator, evidence, tlp, options, cb) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;
  const requestOptions = {
    method: 'POST',
    uri: `${url}api/1_0/evidence`,
    auth: {
      user: options.userName,
      pass: options.password
    },
    formData: {
      tlp,
      evidenceFileClassification: '',
      sourceId: options.evidenceSourceId,
      evidenceFile: {
        value: Buffer.from(
          `Evidence for ${indicator}\nSubmitted from Polarity Analyst1 Integration\n\n${evidence}`,
          'utf-8'
        ),
        options: {
          filename: `polarity-${+new Date()}.txt`,
          contentType: 'text/plain'
        }
      }
    },
    json: true
  };

  Logger.trace({ requestOptions }, 'Evidence request options');

  request(requestOptions, (err, response, body) => {
    if (err) {
      return cb(err);
    }

    Logger.trace({ response }, 'Evidence Upload Response');
    if (response.statusCode === 200) {
      cb(null, {
        uuid: body.uuid
      });
    } else {
      cb({
        detail: `Unexpected status code ${response.statusCode}`,
        body
      });
    }
  });
}

function onMessage(payload, options, cb) {
  switch (payload.action) {
    case 'SUBMIT_EVIDENCE':
      addEvidence(payload.indicator, payload.evidence, payload.tlp, options, (err, result) => {
        if (err) {
          Logger.error(err);
          cb(err);
        } else {
          Logger.trace({ result }, 'Add Evidence Result');
          cb(null, result);
        }
      });
      break;
    case 'CHECK_STATUS':
      checkUploadStatus(payload.uuid, options, (err, result) => {
        if (err) {
          Logger.error(err);
          cb(err);
        } else {
          Logger.trace({ result }, 'Checking upload status');
          cb(null, result);
        }
      });
      break;
  }
}

function handleRestError(error, res, body) {
  let result;

  if (error) {
    return {
      error: parseErrorToReadableJSON(error),
      detail: `HTTP Request Error${error.code ? ': ' + error.code : ''}`
    };
  }
  if (res.statusCode === 200) {
    // we got data!
    result = {
      body
    };
  } else if (res.statusCode === 404) {
    // no result found
    result = {
      body: null
    };
  } else if (res.statusCode === 400) {
    result = {
      error: body,
      detail: '400 - Bad Request Parameters'
    };
  } else if (res.statusCode === 401) {
    result = {
      error: body,
      detail: '401 - Unauthorized: Ensure your credentials are valid'
    };
  } else {
    // unexpected status code
    result = {
      error: body,
      detail: `Unexpected HTTP Status Code ${res.statusCode} received`
    };
  }
  return result;
}

function validateOptions(options, cb) {
  let errors = [];

  if (typeof options.url.value !== 'string' || options.url.value.length === 0) {
    errors.push({
      key: 'url',
      message: 'You must provide a valid url'
    });
  }

  if (typeof options.userName.value !== 'string' || options.userName.value.length === 0) {
    errors.push({
      key: 'userName',
      message: 'You must provide a valid Analyst1 username'
    });
  }

  if (typeof options.password.value !== 'string' || options.password.value.length === 0) {
    errors.push({
      key: 'password',
      message: 'You must provide valid an Analyst1 password'
    });
  }

  if (options.enableEvidenceSubmission.value === true && +options.evidenceSourceId.value <= -1) {
    errors.push({
      key: 'evidenceSourceId',
      message:
        'Evidence source id must be set to a number greater than or equal to zero.  Delete the option value to specify an unknown source.'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  onDetails,
  onMessage,
  validateOptions
};
