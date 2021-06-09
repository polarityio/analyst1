'use strict';

const request = require('request');
const config = require('./config/config');
const get = require('lodash.get');
const async = require('async');
const fs = require('fs');
const fp = require('lodash/fp');
const _ = require('lodash');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;
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

function getIndicatorBulkMatchRequestOptions(entityType, entityValue, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/indicator/bulkMatch`,
    qs: {
      value: entityValue,
      type: _convertPolarityTypeToAnalyst1Type(entityType)
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

function getSearchRequestOptions(entity, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/indicator`,
    qs: {
      searchTerm: entity.value
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

function getCveSearchOptions(entity, options) {
  const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

  return {
    method: 'GET',
    uri: `${url}api/1_0/actor`,
    qs: {
      cve: entity.value
    },
    auth: {
      user: options.userName,
      pass: options.password
    },
    json: true
  };
}

const getEntityValuesForQuery = (entities) => {
  const groupedEntities = fp.groupBy('type', entities);
  const queryParamValues = {};

  for (const [entityType, entityGroup] of Object.entries(groupedEntities)) {
    const values = entityGroup.map((entity) => entity.value).join(',');
    queryParamValues[entityType] = `${values}`;
  }
  return queryParamValues;
};

// ISSUE: Having a single body being passed in [domain, ]
const mapResponsesToEntities = async (entities, body) => {
  const response = [];
  let currentEntity;
  let currentResponse;

  Logger.trace({ BODIES_PASSED_IN_FROM_REQUESTS: body });

  for (let i = 0; i < entities.length; i++) {
    currentEntity = entities[i];
    for (let j = 0; j < body.length; j++) {
      currentResponse = body[j];
      if (currentEntity.value === currentResponse.value.name) {
        response.push({ entity: currentEntity, body: currentResponse });
      }
    }
  }
  Logger.trace({ response }, 'Response');
  return response;
};

const doLookup = async (entities, options, cb) => {
  let lookupResults = [];
  let tasks = [];
  let response;
  let requestOptions;

  entities.forEach((entity) => {
    if (entity.type === 'cve') {
      requestOptions = getCveSearchOptions(entity, options);
    } else if (!options.doIndicatorMatchSearch) {
      requestOptions = getSearchRequestOptions(entity, options);
    }
  });

  Logger.debug({ entities, options }, 'doLookup');

  const queryValues = getEntityValuesForQuery(entities);

  for (const [entityType, entityValue] of Object.entries(queryValues)) {
    // entities.forEach(entity => {
    // iterating over { IPv4: 'ip_1, ip_2', domain: domain }
    // On_iteration_1 - passing in domain, and 'something.com'
    // requestOptions = getIndicatorBulkMatchRequestOptions(entityType, entityValue, options);

    // Logger.trace({ requestOptions }, 'Request Options');

    // Iteration_1_request_options - requestOptions":{"method":"GET","uri":"https://partner.analystplatform.com/api/1_0/indicator/bulkMatch","qs":{"value":"something.com","type":"domain"}
    // requestOptions passed into request
    // a body is returned for Domain -

    //ISSUE: a body will not be returned fro the other entity groups, on
    tasks.push((done) => {
      requestOptions = getIndicatorBulkMatchRequestOptions(entityType, entityValue, options);

      Logger.trace({ requestOptions }, 'Request Options');
      requestWithDefaults(requestOptions, async (error, res, body) => {
        if (error) {
          done(response);
        }

        response = await mapResponsesToEntities(entities, body);
        // need to handle error
        if (error) {
          return cb({
            err: error,
            detail: 'Error making HTTP request'
          });
        }
        done(null, response);
        Logger.trace({ response }, 'builtResponse');
      });
    });
  }

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }
    // mapResponsesToEntities returns the values in an array which is pushed into [tasks]
    // flattening, so the forEach below has access to the values of results in response variable
    results = _.flattenDeep(results);

    results.forEach((result) => {
      if (result.body === null || _isMiss(result.body, options)) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary:
              result.entity.type === 'cve' ? _getCveSummaryTags(result, options) : _getSummaryTags(result, options),
            details: _getDetails(result.entity, result.body)
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
};

function _getDetails(entity, body) {
  if (entity.type === 'cve') {
    let actors = body.results.map((actor) => {
      return {
        name: get(actor, 'title.name', 'No Name'),
        id: get(actor, 'id', null)
      };
    });
    return { actors, results: [] };
  }

  if (Array.isArray(body.results)) {
    return { results: body.results };
  }

  return { totalResults: 1, results: [body] };
}

function _getCveSummaryTags(result, options) {
  const tags = [];
  if (Array.isArray(result.body.results)) {
    for (let i = 0; i < result.body.results.length && i < MAX_ACTORS_IN_SUMMARY; i++) {
      const actor = result.body.results[i];
      const actorName = get(actor, 'title.name');
      if (actorName) {
        tags.push(`Actor: ${actorName}`);
      }
    }
  }

  if (tags.length < result.body.results.length) {
    tags.push(`+${result.body.results.length - tags.length} more actors`);
  }

  return tags;
}

function _getSummaryTags(result, options) {
  const tags = [];

  if (options.doIndicatorMatchSearch) {
    tags.push(`TLP: ${result.body.tlp}`);
    tags.push(`Reports: ${result.body.reportCount}`);
  } else {
    tags.push(`Results: ${result.body.totalResults}`);
  }

  if (Array.isArray(result.body.actors)) {
    result.body.actors.forEach((actor) => {
      tags.push(`Actor: ${actor.name}`);
    });
  }

  return tags;
}

const _isMiss = (body, options) => {
  if (body === null || typeof body === 'undefined') {
    return true;
  }

  let noValidReturnValues;
  if (options.doIndicatorMatchSearch) {
    // misses are handled via a 404 return code so we don't need to check the payload
    noValidReturnValues = false;
  } else {
    noValidReturnValues = !(Array.isArray(body.results) && body.results.length > 0);
  }

  return noValidReturnValues;
};

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
    let processedResult = handleRestError(error, entity, result, body);
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

function handleRestError(error, entity, res, body) {
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
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 404) {
    // no result found
    result = {
      entity: entity,
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
