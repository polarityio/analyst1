'use strict';

const request = require('request');
const config = require('./config/config');
const get = require('lodash.get');
const groupBy = require('lodash.groupby');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 5;
const MAX_ACTORS_IN_SUMMARY = 5;

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
    uri: `${url}api/1_0/indicator/bulkMatch`,
    qs: {
      value: searchString,
      type: _convertPolarityTypeToAnalyst1Type(entityType)
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
      cve: cveEntity.value
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
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
    if (Array.isArray(result.body)) {
      result.body.forEach((indicatorResult) => {
        const entityValue = get(indicatorResult, 'value.name', '').toLowerCase();
        const entity = entityLookup.get(entityValue);
        if (!entity) {
          // somehow the returned entity value does not match anything in our entity lookup so
          // we just skip it
          Logger.error({ indicatorResult }, 'Indicator Result is missing `value.name`');
          return;
        }
        entityLookup.delete(entityValue);
        const details = _getDetails(entity, indicatorResult, options);
        if (details && details.results.length > 0) {
          lookupResults.push({
            entity,
            data: {
              summary: _getSummaryTags(indicatorResult, options),
              details
            }
          });
        } else {
          lookupResults.push({
            entity,
            data: null
          });
        }
      });

      // Any entities left in our lookup map did not have a hit so we create a miss for them
      Array.from(entityLookup.values()).forEach((entity) => {
        lookupResults.push({
          entity,
          data: null
        });
      });
    }
    cb(null, lookupResults);
  });
}

function doLookup(entities, options, cb) {
  let lookupResults = [];

  Logger.debug({ entities, options }, 'doLookup');

  const groupedEntities = groupBy(entities, 'type');

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
      cb(err, lookupResults);
    }
  );
}

function _getDetails(entity, body, options) {
  Logger.trace({ body }, '_getDetails');

  if (entity.type === 'cve') {
    let actors = body.results.map((actor) => {
      return {
        name: get(actor, 'title.name', 'No Name'),
        id: get(actor, 'id', null)
      };
    });
    return { actors, results: [] };
  }

  let result;
  if (Array.isArray(body.results)) {
    result = body.results;
  } else {
    result = [body];
  }

  return { results: options.verifiedOnly ? result.filter((indicator) => indicator.verified) : result };
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

  tags.push(`TLP: ${body.tlp}`);
  tags.push(`Reports: ${body.reportCount}`);

  if (Array.isArray(body.actors)) {
    body.actors.forEach((actor) => {
      tags.push(`Actor: ${actor.name}`);
    });
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
    cb(null, lookupResult.data);
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

function handleRestError(error, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
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

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  onDetails,
  validateOptions
};
