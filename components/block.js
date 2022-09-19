polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  webUrl: Ember.computed('block.userOptions.url', function () {
    const url = this.get('block.userOptions.url');
    return url.endsWith('/') ? url : `${url}/`;
  }),
  tlpValues: [
    {
      value: 'undetermined',
      display: 'Undetermined'
    },
    {
      value: 'white',
      display: 'White'
    },
    {
      value: 'green',
      display: 'Green'
    },
    {
      value: 'amber',
      display: 'Amber'
    },
    {
      value: 'red',
      display: 'Red'
    }
  ],
  init() {
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.evidence', '');
      this.set('block._state.showEvidenceSubmission', false);
      this.set('block._state.tlp', this.get('block.userOptions.defaultEvidenceTlp.value'));
    }

    this._super(...arguments);
  },
  actions: {
    submitEvidence: function () {
      this.set('block._state.submitMessage', 'Submitting evidence to Analyst1');
      this.set('block._state.evidenceIsSubmitting', true);
      this.set('block._state.searchRunning', true);
      this.set('block._state.error', '');

      const payload = {
        action: 'SUBMIT_EVIDENCE',
        evidence: this.get('block._state.evidence'),
        indicator: this.get('block.entity.value'),
        tlp: this.get('block._state.tlp')
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          // this returns the uuid of the upload which we can use to query the status
          this.set('block._state.uuid', result.uuid);
          setTimeout(() => {
            if(!this.isDestroyed) {
              this.checkUploadStatus()
            }
          }, 2000);
          this.set('block._state.submitMessage', 'Checking upload status');
        })
        .catch((e) => {
          this.set('block._state.error', JSON.stringify(e, null, 4));
          this.set('block._state.evidenceIsSubmitting', false);
        })
        .finally(() => {
          this.set('block._state.searchRunning', false);
        });
    }
  },
  checkUploadStatus(checkCount = 1) {
    if(this.isDestroyed){
      return;
    }

    if(checkCount >= 10){
      this.set('block._state.submitMessage', `Analyst1's evidence processing is taking longer than expected. To view final results, open Analyst1.`);
      this.set('block._state.evidenceIsSubmitting', false);
      setTimeout(() => {
        if(!this.isDestroyed){
          this.set('block._state.submitMessage', '');
        }
      }, 7000)
      return;
    }

    const payload = {
      action: 'CHECK_STATUS',
      uuid: this.get('block._state.uuid')
    };
    this.set('block._state.submitMessage', `Checking upload status [${checkCount}]`);
    this.set('block._state.checkingUploadStatus', true);

    this.sendIntegrationMessage(payload)
      .then((result) => {
        if (result.isComplete) {
          this.set('block._state.evidenceId', result.evidenceId);
          this.set('block._state.evidenceIsSubmitting', false);
          this.set('block._state.submitMessage', '');
          this.set('block._state.uuid', '');
          this.set('block._state.evidence', '')
        } else {
          setTimeout(() => {
            if(!this.isDestroyed) {
              this.checkUploadStatus(++checkCount);
            }
          }, 3000);
        }
      })
      .catch((e) => {
        this.set('block._state.error', JSON.stringify(e, null, 4));
        this.set('block._state.evidenceIsSubmitting', false);
        this.set('block._state.submitMessage', '');
        this.set('block._state.uuid', '');
      })
      .finally(() => {
        this.set('block._state.checkingUploadStatus', false);
      });
  }
});
