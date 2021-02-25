(window.webpackJsonp=window.webpackJsonp||[]).push([[259],{692:function(e,d,t){"use strict";t.r(d);var a=t(1),n=Object(a.a)({},(function(){var e=this,d=e.$createElement,t=e._self._c||d;return t("ContentSlotsDistributor",{attrs:{"slot-key":e.$parent.slotKey}},[t("h1",{attrs:{id:"state"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#state"}},[e._v("#")]),e._v(" State")]),e._v(" "),t("h2",{attrs:{id:"lasttotalpower"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#lasttotalpower"}},[e._v("#")]),e._v(" LastTotalPower")]),e._v(" "),t("p",[e._v("LastTotalPower tracks the total amounts of bonded tokens recorded during the previous end block.")]),e._v(" "),t("ul",[t("li",[e._v("LastTotalPower: "),t("code",[e._v("0x12 -> ProtocolBuffer(sdk.Int)")])])]),e._v(" "),t("h2",{attrs:{id:"params"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#params"}},[e._v("#")]),e._v(" Params")]),e._v(" "),t("p",[e._v("Params is a module-wide configuration structure that stores system parameters\nand defines overall functioning of the staking module.")]),e._v(" "),t("ul",[t("li",[e._v("Params: "),t("code",[e._v('Paramsspace("staking") -> legacy_amino(params)')])])]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gUGFyYW1zIGRlZmluZXMgdGhlIHBhcmFtZXRlcnMgZm9yIHRoZSBzdGFraW5nIG1vZHVsZS4KbWVzc2FnZSBQYXJhbXMgewogIG9wdGlvbiAoZ29nb3Byb3RvLmVxdWFsKSAgICAgICAgICAgID0gdHJ1ZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX3N0cmluZ2VyKSA9IGZhbHNlOwoKICBnb29nbGUucHJvdG9idWYuRHVyYXRpb24gdW5ib25kaW5nX3RpbWUgPSAxCiAgICAgIFsoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlLCAoZ29nb3Byb3RvLnN0ZGR1cmF0aW9uKSA9IHRydWUsIChnb2dvcHJvdG8ubW9yZXRhZ3MpID0gJnF1b3Q7eWFtbDpcJnF1b3Q7dW5ib25kaW5nX3RpbWVcJnF1b3Q7JnF1b3Q7XTsKICB1aW50MzIgbWF4X3ZhbGlkYXRvcnMgICAgID0gMiBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDttYXhfdmFsaWRhdG9yc1wmcXVvdDsmcXVvdDtdOwogIHVpbnQzMiBtYXhfZW50cmllcyAgICAgICAgPSAzIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O21heF9lbnRyaWVzXCZxdW90OyZxdW90O107CiAgdWludDMyIGhpc3RvcmljYWxfZW50cmllcyA9IDQgWyhnb2dvcHJvdG8ubW9yZXRhZ3MpID0gJnF1b3Q7eWFtbDpcJnF1b3Q7aGlzdG9yaWNhbF9lbnRyaWVzXCZxdW90OyZxdW90O107CiAgc3RyaW5nIGJvbmRfZGVub20gICAgICAgICA9IDUgWyhnb2dvcHJvdG8ubW9yZXRhZ3MpID0gJnF1b3Q7eWFtbDpcJnF1b3Q7Ym9uZF9kZW5vbVwmcXVvdDsmcXVvdDtdOwp9"}})],1),e._v(" "),t("h2",{attrs:{id:"validator"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#validator"}},[e._v("#")]),e._v(" Validator")]),e._v(" "),t("p",[e._v("Validators can have one of three statuses")]),e._v(" "),t("ul",[t("li",[t("code",[e._v("Unbonded")]),e._v(": The validator is not in the active set. They cannot sign blocks and do not earn\nrewards. They can receive delegations.")]),e._v(" "),t("li",[t("code",[e._v("Bonded")]),e._v('": Once the validator receives sufficient bonded tokens they automtically join the\nactive set during '),t("RouterLink",{attrs:{to:"/modules/staking/05_end_block.html#validator-set-changes"}},[t("code",[e._v("EndBlock")])]),e._v(" and their status is updated to "),t("code",[e._v("Bonded")]),e._v(".\nThey are signing blocks and receiving rewards. They can receive further delegations.\nThey can be slashed for misbehavior. Delegators to this validator who unbond their delegation\nmust wait the duration of the UnbondingTime, a chain-specific param. during which time\nthey are still slashable for offences of the source validator if those offences were committed\nduring the period of time that the tokens were bonded.")],1),e._v(" "),t("li",[t("code",[e._v("Unbonding")]),e._v(": When a validator leaves the active set, either by choice or due to slashing or\ntombstoning, an unbonding of all their delegations begins. All delegations must then wait the UnbondingTime\nbefore moving receiving their tokens to their accounts from the "),t("code",[e._v("BondedPool")]),e._v(".")])]),e._v(" "),t("p",[e._v("Validators objects should be primarily stored and accessed by the\n"),t("code",[e._v("OperatorAddr")]),e._v(", an SDK validator address for the operator of the validator. Two\nadditional indices are maintained per validator object in order to fulfill\nrequired lookups for slashing and validator-set updates. A third special index\n("),t("code",[e._v("LastValidatorPower")]),e._v(") is also maintained which however remains constant\nthroughout each block, unlike the first two indices which mirror the validator\nrecords within a block.")]),e._v(" "),t("ul",[t("li",[e._v("Validators: "),t("code",[e._v("0x21 | OperatorAddrLen (1 byte) | OperatorAddr -> ProtocolBuffer(validator)")])]),e._v(" "),t("li",[e._v("ValidatorsByConsAddr: "),t("code",[e._v("0x22 | ConsAddrLen (1 byte) | ConsAddr -> OperatorAddr")])]),e._v(" "),t("li",[e._v("ValidatorsByPower: "),t("code",[e._v("0x23 | BigEndian(ConsensusPower) | OperatorAddrLen (1 byte) | OperatorAddr -> OperatorAddr")])]),e._v(" "),t("li",[e._v("LastValidatorsPower: "),t("code",[e._v("0x11 | OperatorAddrLen (1 byte) | OperatorAddr -> ProtocolBuffer(ConsensusPower)")])])]),e._v(" "),t("p",[t("code",[e._v("Validators")]),e._v(" is the primary index - it ensures that each operator can have only one\nassociated validator, where the public key of that validator can change in the\nfuture. Delegators can refer to the immutable operator of the validator, without\nconcern for the changing public key.")]),e._v(" "),t("p",[t("code",[e._v("ValidatorByConsAddr")]),e._v(" is an additional index that enables lookups for slashing.\nWhen Tendermint reports evidence, it provides the validator address, so this\nmap is needed to find the operator. Note that the "),t("code",[e._v("ConsAddr")]),e._v(" corresponds to the\naddress which can be derived from the validator's "),t("code",[e._v("ConsPubKey")]),e._v(".")]),e._v(" "),t("p",[t("code",[e._v("ValidatorsByPower")]),e._v(" is an additional index that provides a sorted list o\npotential validators to quickly determine the current active set. Here\nConsensusPower is validator.Tokens/10^6. Note that all validators where\n"),t("code",[e._v("Jailed")]),e._v(" is true are not stored within this index.")]),e._v(" "),t("p",[t("code",[e._v("LastValidatorsPower")]),e._v(" is a special index that provides a historical list of the\nlast-block's bonded validators. This index remains constant during a block but\nis updated during the validator set update process which takes place in "),t("RouterLink",{attrs:{to:"/modules/staking/05_end_block.html"}},[t("code",[e._v("EndBlock")])]),e._v(".")],1),e._v(" "),t("p",[e._v("Each validator's state is stored in a "),t("code",[e._v("Validator")]),e._v(" struct:")]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gVmFsaWRhdG9yIGRlZmluZXMgYSB2YWxpZGF0b3IsIHRvZ2V0aGVyIHdpdGggdGhlIHRvdGFsIGFtb3VudCBvZiB0aGUKLy8gVmFsaWRhdG9yJ3MgYm9uZCBzaGFyZXMgYW5kIHRoZWlyIGV4Y2hhbmdlIHJhdGUgdG8gY29pbnMuIFNsYXNoaW5nIHJlc3VsdHMgaW4KLy8gYSBkZWNyZWFzZSBpbiB0aGUgZXhjaGFuZ2UgcmF0ZSwgYWxsb3dpbmcgY29ycmVjdCBjYWxjdWxhdGlvbiBvZiBmdXR1cmUKLy8gdW5kZWxlZ2F0aW9ucyB3aXRob3V0IGl0ZXJhdGluZyBvdmVyIGRlbGVnYXRvcnMuIFdoZW4gY29pbnMgYXJlIGRlbGVnYXRlZCB0bwovLyB0aGlzIHZhbGlkYXRvciwgdGhlIHZhbGlkYXRvciBpcyBjcmVkaXRlZCB3aXRoIGEgZGVsZWdhdGlvbiB3aG9zZSBudW1iZXIgb2YKLy8gYm9uZCBzaGFyZXMgaXMgYmFzZWQgb24gdGhlIGFtb3VudCBvZiBjb2lucyBkZWxlZ2F0ZWQgZGl2aWRlZCBieSB0aGUgY3VycmVudAovLyBleGNoYW5nZSByYXRlLiBWb3RpbmcgcG93ZXIgY2FuIGJlIGNhbGN1bGF0ZWQgYXMgdG90YWwgYm9uZGVkIHNoYXJlcwovLyBtdWx0aXBsaWVkIGJ5IGV4Y2hhbmdlIHJhdGUuCm1lc3NhZ2UgVmFsaWRhdG9yIHsKICBvcHRpb24gKGdvZ29wcm90by5lcXVhbCkgICAgICAgICAgICA9IGZhbHNlOwogIG9wdGlvbiAoZ29nb3Byb3RvLmdvcHJvdG9fc3RyaW5nZXIpID0gZmFsc2U7CiAgb3B0aW9uIChnb2dvcHJvdG8uZ29wcm90b19nZXR0ZXJzKSAgPSBmYWxzZTsKCiAgc3RyaW5nICAgICAgICAgICAgICBvcGVyYXRvcl9hZGRyZXNzID0gMSBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDtvcGVyYXRvcl9hZGRyZXNzXCZxdW90OyZxdW90O107CiAgZ29vZ2xlLnByb3RvYnVmLkFueSBjb25zZW5zdXNfcHVia2V5ID0gMgogICAgICBbKGNvc21vc19wcm90by5hY2NlcHRzX2ludGVyZmFjZSkgPSAmcXVvdDtjb3Ntb3MuY3J5cHRvLlB1YktleSZxdW90OywgKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDtjb25zZW5zdXNfcHVia2V5XCZxdW90OyZxdW90O107CiAgYm9vbCAgICAgICBqYWlsZWQgPSAzOwogIEJvbmRTdGF0dXMgc3RhdHVzID0gNDsKICBzdHJpbmcgdG9rZW5zID0gNSBbKGdvZ29wcm90by5jdXN0b210eXBlKSA9ICZxdW90O2dpdGh1Yi5jb20vY29zbW9zL2Nvc21vcy1zZGsvdHlwZXMuSW50JnF1b3Q7LCAoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlXTsKICBzdHJpbmcgZGVsZWdhdG9yX3NoYXJlcyA9IDYgWwogICAgKGdvZ29wcm90by5tb3JldGFncykgICA9ICZxdW90O3lhbWw6XCZxdW90O2RlbGVnYXRvcl9zaGFyZXNcJnF1b3Q7JnF1b3Q7LAogICAgKGdvZ29wcm90by5jdXN0b210eXBlKSA9ICZxdW90O2dpdGh1Yi5jb20vY29zbW9zL2Nvc21vcy1zZGsvdHlwZXMuRGVjJnF1b3Q7LAogICAgKGdvZ29wcm90by5udWxsYWJsZSkgICA9IGZhbHNlCiAgXTsKICBEZXNjcmlwdGlvbiAgICAgICAgICAgICAgIGRlc2NyaXB0aW9uICAgICAgPSA3IFsoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlXTsKICBpbnQ2NCAgICAgICAgICAgICAgICAgICAgIHVuYm9uZGluZ19oZWlnaHQgPSA4IFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O3VuYm9uZGluZ19oZWlnaHRcJnF1b3Q7JnF1b3Q7XTsKICBnb29nbGUucHJvdG9idWYuVGltZXN0YW1wIHVuYm9uZGluZ190aW1lICAgPSA5CiAgICAgIFsoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlLCAoZ29nb3Byb3RvLnN0ZHRpbWUpID0gdHJ1ZSwgKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDt1bmJvbmRpbmdfdGltZVwmcXVvdDsmcXVvdDtdOwogIENvbW1pc3Npb24gY29tbWlzc2lvbiAgICAgICAgICA9IDEwIFsoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlXTsKICBzdHJpbmcgICAgIG1pbl9zZWxmX2RlbGVnYXRpb24gPSAxMSBbCiAgICAoZ29nb3Byb3RvLm1vcmV0YWdzKSAgID0gJnF1b3Q7eWFtbDpcJnF1b3Q7bWluX3NlbGZfZGVsZWdhdGlvblwmcXVvdDsmcXVvdDssCiAgICAoZ29nb3Byb3RvLmN1c3RvbXR5cGUpID0gJnF1b3Q7Z2l0aHViLmNvbS9jb3Ntb3MvY29zbW9zLXNkay90eXBlcy5JbnQmcXVvdDssCiAgICAoZ29nb3Byb3RvLm51bGxhYmxlKSAgID0gZmFsc2UKICBdOwp9"}})],1),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gQ29tbWlzc2lvblJhdGVzIGRlZmluZXMgdGhlIGluaXRpYWwgY29tbWlzc2lvbiByYXRlcyB0byBiZSB1c2VkIGZvciBjcmVhdGluZwovLyBhIHZhbGlkYXRvci4KbWVzc2FnZSBDb21taXNzaW9uUmF0ZXMgewogIG9wdGlvbiAoZ29nb3Byb3RvLmVxdWFsKSAgICAgICAgICAgID0gdHJ1ZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX3N0cmluZ2VyKSA9IGZhbHNlOwoKICBzdHJpbmcgcmF0ZSAgICAgPSAxIFsoZ29nb3Byb3RvLmN1c3RvbXR5cGUpID0gJnF1b3Q7Z2l0aHViLmNvbS9jb3Ntb3MvY29zbW9zLXNkay90eXBlcy5EZWMmcXVvdDssIChnb2dvcHJvdG8ubnVsbGFibGUpID0gZmFsc2VdOwogIHN0cmluZyBtYXhfcmF0ZSA9IDIgWwogICAgKGdvZ29wcm90by5tb3JldGFncykgICA9ICZxdW90O3lhbWw6XCZxdW90O21heF9yYXRlXCZxdW90OyZxdW90OywKICAgIChnb2dvcHJvdG8uY3VzdG9tdHlwZSkgPSAmcXVvdDtnaXRodWIuY29tL2Nvc21vcy9jb3Ntb3Mtc2RrL3R5cGVzLkRlYyZxdW90OywKICAgIChnb2dvcHJvdG8ubnVsbGFibGUpICAgPSBmYWxzZQogIF07CiAgc3RyaW5nIG1heF9jaGFuZ2VfcmF0ZSA9IDMgWwogICAgKGdvZ29wcm90by5tb3JldGFncykgICA9ICZxdW90O3lhbWw6XCZxdW90O21heF9jaGFuZ2VfcmF0ZVwmcXVvdDsmcXVvdDssCiAgICAoZ29nb3Byb3RvLmN1c3RvbXR5cGUpID0gJnF1b3Q7Z2l0aHViLmNvbS9jb3Ntb3MvY29zbW9zLXNkay90eXBlcy5EZWMmcXVvdDssCiAgICAoZ29nb3Byb3RvLm51bGxhYmxlKSAgID0gZmFsc2UKICBdOwp9CgovLyBDb21taXNzaW9uIGRlZmluZXMgY29tbWlzc2lvbiBwYXJhbWV0ZXJzIGZvciBhIGdpdmVuIHZhbGlkYXRvci4KbWVzc2FnZSBDb21taXNzaW9uIHsKICBvcHRpb24gKGdvZ29wcm90by5lcXVhbCkgICAgICAgICAgICA9IHRydWU7CiAgb3B0aW9uIChnb2dvcHJvdG8uZ29wcm90b19zdHJpbmdlcikgPSBmYWxzZTsKCiAgQ29tbWlzc2lvblJhdGVzICAgICAgICAgICBjb21taXNzaW9uX3JhdGVzID0gMSBbKGdvZ29wcm90by5lbWJlZCkgPSB0cnVlLCAoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlXTsKICBnb29nbGUucHJvdG9idWYuVGltZXN0YW1wIHVwZGF0ZV90aW1lICAgICAgPSAyCiAgICAgIFsoZ29nb3Byb3RvLm51bGxhYmxlKSA9IGZhbHNlLCAoZ29nb3Byb3RvLnN0ZHRpbWUpID0gdHJ1ZSwgKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDt1cGRhdGVfdGltZVwmcXVvdDsmcXVvdDtdOwp9CgovLyBEZXNjcmlwdGlvbiBkZWZpbmVzIGEgdmFsaWRhdG9yIGRlc2NyaXB0aW9uLgptZXNzYWdlIERlc2NyaXB0aW9uIHsKICBvcHRpb24gKGdvZ29wcm90by5lcXVhbCkgICAgICAgICAgICA9IHRydWU7CiAgb3B0aW9uIChnb2dvcHJvdG8uZ29wcm90b19zdHJpbmdlcikgPSBmYWxzZTsKCiAgc3RyaW5nIG1vbmlrZXIgICAgICAgICAgPSAxOwogIHN0cmluZyBpZGVudGl0eSAgICAgICAgID0gMjsKICBzdHJpbmcgd2Vic2l0ZSAgICAgICAgICA9IDM7CiAgc3RyaW5nIHNlY3VyaXR5X2NvbnRhY3QgPSA0IFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O3NlY3VyaXR5X2NvbnRhY3RcJnF1b3Q7JnF1b3Q7XTsKICBzdHJpbmcgZGV0YWlscyAgICAgICAgICA9IDU7Cn0="}})],1),e._v(" "),t("h2",{attrs:{id:"delegation"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#delegation"}},[e._v("#")]),e._v(" Delegation")]),e._v(" "),t("p",[e._v("Delegations are identified by combining "),t("code",[e._v("DelegatorAddr")]),e._v(" (the address of the delegator)\nwith the "),t("code",[e._v("ValidatorAddr")]),e._v(" Delegators are indexed in the store as follows:")]),e._v(" "),t("ul",[t("li",[e._v("Delegation: "),t("code",[e._v("0x31 | DelegatorAddrLen (1 byte) | DelegatorAddr | ValidatorAddrLen (1 byte) | ValidatorAddr -> ProtocolBuffer(delegation)")])])]),e._v(" "),t("p",[e._v("Stake holders may delegate coins to validators; under this circumstance their\nfunds are held in a "),t("code",[e._v("Delegation")]),e._v(" data structure. It is owned by one\ndelegator, and is associated with the shares for one validator. The sender of\nthe transaction is the owner of the bond.")]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gRGVsZWdhdGlvbiByZXByZXNlbnRzIHRoZSBib25kIHdpdGggdG9rZW5zIGhlbGQgYnkgYW4gYWNjb3VudC4gSXQgaXMKLy8gb3duZWQgYnkgb25lIGRlbGVnYXRvciwgYW5kIGlzIGFzc29jaWF0ZWQgd2l0aCB0aGUgdm90aW5nIHBvd2VyIG9mIG9uZQovLyB2YWxpZGF0b3IuCm1lc3NhZ2UgRGVsZWdhdGlvbiB7CiAgb3B0aW9uIChnb2dvcHJvdG8uZXF1YWwpICAgICAgICAgICAgPSBmYWxzZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX2dldHRlcnMpICA9IGZhbHNlOwogIG9wdGlvbiAoZ29nb3Byb3RvLmdvcHJvdG9fc3RyaW5nZXIpID0gZmFsc2U7CgogIHN0cmluZyBkZWxlZ2F0b3JfYWRkcmVzcyA9IDEgWyhnb2dvcHJvdG8ubW9yZXRhZ3MpID0gJnF1b3Q7eWFtbDpcJnF1b3Q7ZGVsZWdhdG9yX2FkZHJlc3NcJnF1b3Q7JnF1b3Q7XTsKICBzdHJpbmcgdmFsaWRhdG9yX2FkZHJlc3MgPSAyIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O3ZhbGlkYXRvcl9hZGRyZXNzXCZxdW90OyZxdW90O107CiAgc3RyaW5nIHNoYXJlcyA9IDMgWyhnb2dvcHJvdG8uY3VzdG9tdHlwZSkgPSAmcXVvdDtnaXRodWIuY29tL2Nvc21vcy9jb3Ntb3Mtc2RrL3R5cGVzLkRlYyZxdW90OywgKGdvZ29wcm90by5udWxsYWJsZSkgPSBmYWxzZV07Cn0="}})],1),e._v(" "),t("h3",{attrs:{id:"delegator-shares"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#delegator-shares"}},[e._v("#")]),e._v(" Delegator Shares")]),e._v(" "),t("p",[e._v("When one Delegates tokens to a Validator they are issued a number of delegator shares based on a\ndynamic exchange rate, calculated as follows from the total number of tokens delegated to the\nvalidator and the number of shares issued so far:")]),e._v(" "),t("p",[t("code",[e._v("Shares per Token = validator.TotalShares() / validator.Tokens()")])]),e._v(" "),t("p",[e._v("Only the number of shares received is stored on the DelegationEntry. When a delegator then\nUndelegates, the token amount they receive is calculated from the number of shares they currently\nhold and the inverse exchange rate:")]),e._v(" "),t("p",[t("code",[e._v("Tokens per Share = validator.Tokens() / validatorShares()")])]),e._v(" "),t("p",[e._v("These "),t("code",[e._v("Shares")]),e._v(" are simply an accounting mechanism. They are not a fungible asset. The reason for\nthis mechanism is to simplify the accounting around slashing. Rather than iteratively slashing the\ntokens of every delegation entry, instead the Validators total bonded tokens can be slashed,\neffectively reducing the value of each issued delegator share.")]),e._v(" "),t("h2",{attrs:{id:"unbondingdelegation"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#unbondingdelegation"}},[e._v("#")]),e._v(" UnbondingDelegation")]),e._v(" "),t("p",[e._v("Shares in a "),t("code",[e._v("Delegation")]),e._v(" can be unbonded, but they must for some time exist as\nan "),t("code",[e._v("UnbondingDelegation")]),e._v(", where shares can be reduced if Byzantine behavior is\ndetected.")]),e._v(" "),t("p",[t("code",[e._v("UnbondingDelegation")]),e._v(" are indexed in the store as:")]),e._v(" "),t("ul",[t("li",[e._v("UnbondingDelegation: "),t("code",[e._v("0x32 | DelegatorAddrLen (1 byte) | DelegatorAddr | ValidatorAddrLen (1 byte) | ValidatorAddr -> ProtocolBuffer(unbondingDelegation)")])]),e._v(" "),t("li",[e._v("UnbondingDelegationsFromValidator: "),t("code",[e._v("0x33 | ValidatorAddrLen (1 byte) | ValidatorAddr | DelegatorAddrLen (1 byte) | DelegatorAddr -> nil")])])]),e._v(" "),t("p",[e._v("The first map here is used in queries, to lookup all unbonding delegations for\na given delegator, while the second map is used in slashing, to lookup all\nunbonding delegations associated with a given validator that need to be\nslashed.")]),e._v(" "),t("p",[e._v("A UnbondingDelegation object is created every time an unbonding is initiated.")]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gVW5ib25kaW5nRGVsZWdhdGlvbiBzdG9yZXMgYWxsIG9mIGEgc2luZ2xlIGRlbGVnYXRvcidzIHVuYm9uZGluZyBib25kcwovLyBmb3IgYSBzaW5nbGUgdmFsaWRhdG9yIGluIGFuIHRpbWUtb3JkZXJlZCBsaXN0LgptZXNzYWdlIFVuYm9uZGluZ0RlbGVnYXRpb24gewogIG9wdGlvbiAoZ29nb3Byb3RvLmVxdWFsKSAgICAgICAgICAgID0gZmFsc2U7CiAgb3B0aW9uIChnb2dvcHJvdG8uZ29wcm90b19nZXR0ZXJzKSAgPSBmYWxzZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX3N0cmluZ2VyKSA9IGZhbHNlOwoKICBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZWdhdG9yX2FkZHJlc3MgPSAxIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O2RlbGVnYXRvcl9hZGRyZXNzXCZxdW90OyZxdW90O107CiAgc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRvcl9hZGRyZXNzID0gMiBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDt2YWxpZGF0b3JfYWRkcmVzc1wmcXVvdDsmcXVvdDtdOwogIHJlcGVhdGVkIFVuYm9uZGluZ0RlbGVnYXRpb25FbnRyeSBlbnRyaWVzID0gMyBbKGdvZ29wcm90by5udWxsYWJsZSkgPSBmYWxzZV07IC8vIHVuYm9uZGluZyBkZWxlZ2F0aW9uIGVudHJpZXMKfQoKLy8gVW5ib25kaW5nRGVsZWdhdGlvbkVudHJ5IGRlZmluZXMgYW4gdW5ib25kaW5nIG9iamVjdCB3aXRoIHJlbGV2YW50IG1ldGFkYXRhLgptZXNzYWdlIFVuYm9uZGluZ0RlbGVnYXRpb25FbnRyeSB7CiAgb3B0aW9uIChnb2dvcHJvdG8uZXF1YWwpICAgICAgICAgICAgPSB0cnVlOwogIG9wdGlvbiAoZ29nb3Byb3RvLmdvcHJvdG9fc3RyaW5nZXIpID0gZmFsc2U7CgogIGludDY0ICAgICAgICAgICAgICAgICAgICAgY3JlYXRpb25faGVpZ2h0ID0gMSBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDtjcmVhdGlvbl9oZWlnaHRcJnF1b3Q7JnF1b3Q7XTsKICBnb29nbGUucHJvdG9idWYuVGltZXN0YW1wIGNvbXBsZXRpb25fdGltZSA9IDIKICAgICAgWyhnb2dvcHJvdG8ubnVsbGFibGUpID0gZmFsc2UsIChnb2dvcHJvdG8uc3RkdGltZSkgPSB0cnVlLCAoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O2NvbXBsZXRpb25fdGltZVwmcXVvdDsmcXVvdDtdOwogIHN0cmluZyBpbml0aWFsX2JhbGFuY2UgPSAzIFsKICAgIChnb2dvcHJvdG8uY3VzdG9tdHlwZSkgPSAmcXVvdDtnaXRodWIuY29tL2Nvc21vcy9jb3Ntb3Mtc2RrL3R5cGVzLkludCZxdW90OywKICAgIChnb2dvcHJvdG8ubnVsbGFibGUpICAgPSBmYWxzZSwKICAgIChnb2dvcHJvdG8ubW9yZXRhZ3MpICAgPSAmcXVvdDt5YW1sOlwmcXVvdDtpbml0aWFsX2JhbGFuY2VcJnF1b3Q7JnF1b3Q7CiAgXTsKICBzdHJpbmcgYmFsYW5jZSA9IDQgWyhnb2dvcHJvdG8uY3VzdG9tdHlwZSkgPSAmcXVvdDtnaXRodWIuY29tL2Nvc21vcy9jb3Ntb3Mtc2RrL3R5cGVzLkludCZxdW90OywgKGdvZ29wcm90by5udWxsYWJsZSkgPSBmYWxzZV07Cn0="}})],1),e._v(" "),t("h2",{attrs:{id:"redelegation"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#redelegation"}},[e._v("#")]),e._v(" Redelegation")]),e._v(" "),t("p",[e._v("The bonded tokens worth of a "),t("code",[e._v("Delegation")]),e._v(" may be instantly redelegated from a\nsource validator to a different validator (destination validator). However when\nthis occurs they must be tracked in a "),t("code",[e._v("Redelegation")]),e._v(" object, whereby their\nshares can be slashed if their tokens have contributed to a Byzantine fault\ncommitted by the source validator.")]),e._v(" "),t("p",[t("code",[e._v("Redelegation")]),e._v(" are indexed in the store as:")]),e._v(" "),t("ul",[t("li",[e._v("Redelegations: "),t("code",[e._v("0x34 | DelegatorAddrLen (1 byte) | DelegatorAddr | ValidatorAddrLen (1 byte) | ValidatorSrcAddr | ValidatorDstAddr -> ProtocolBuffer(redelegation)")])]),e._v(" "),t("li",[e._v("RedelegationsBySrc: "),t("code",[e._v("0x35 | ValidatorSrcAddrLen (1 byte) | ValidatorSrcAddr | ValidatorDstAddrLen (1 byte) | ValidatorDstAddr | DelegatorAddrLen (1 byte) | DelegatorAddr -> nil")])]),e._v(" "),t("li",[e._v("RedelegationsByDst: "),t("code",[e._v("0x36 | ValidatorDstAddrLen (1 byte) | ValidatorDstAddr | ValidatorSrcAddrLen (1 byte) | ValidatorSrcAddr | DelegatorAddrLen (1 byte) | DelegatorAddr -> nil")])])]),e._v(" "),t("p",[e._v("The first map here is used for queries, to lookup all redelegations for a given\ndelegator. The second map is used for slashing based on the "),t("code",[e._v("ValidatorSrcAddr")]),e._v(",\nwhile the third map is for slashing based on the "),t("code",[e._v("ValidatorDstAddr")]),e._v(".")]),e._v(" "),t("p",[e._v('A redelegation object is created every time a redelegation occurs. To prevent\n"redelegation hopping" redelegations may not occur under the situation that:')]),e._v(" "),t("ul",[t("li",[e._v("the (re)delegator already has another immature redelegation in progress\nwith a destination to a validator (let's call it "),t("code",[e._v("Validator X")]),e._v(")")]),e._v(" "),t("li",[e._v("and, the (re)delegator is attempting to create a "),t("em",[e._v("new")]),e._v(" redelegation\nwhere the source validator for this new redelegation is "),t("code",[e._v("Validator-X")]),e._v(".")])]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gUmVkZWxlZ2F0aW9uRW50cnkgZGVmaW5lcyBhIHJlZGVsZWdhdGlvbiBvYmplY3Qgd2l0aCByZWxldmFudCBtZXRhZGF0YS4KbWVzc2FnZSBSZWRlbGVnYXRpb25FbnRyeSB7CiAgb3B0aW9uIChnb2dvcHJvdG8uZXF1YWwpICAgICAgICAgICAgPSB0cnVlOwogIG9wdGlvbiAoZ29nb3Byb3RvLmdvcHJvdG9fc3RyaW5nZXIpID0gZmFsc2U7CgogIGludDY0ICAgICAgICAgICAgICAgICAgICAgY3JlYXRpb25faGVpZ2h0ID0gMSBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDtjcmVhdGlvbl9oZWlnaHRcJnF1b3Q7JnF1b3Q7XTsKICBnb29nbGUucHJvdG9idWYuVGltZXN0YW1wIGNvbXBsZXRpb25fdGltZSA9IDIKICAgICAgWyhnb2dvcHJvdG8ubnVsbGFibGUpID0gZmFsc2UsIChnb2dvcHJvdG8uc3RkdGltZSkgPSB0cnVlLCAoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O2NvbXBsZXRpb25fdGltZVwmcXVvdDsmcXVvdDtdOwogIHN0cmluZyBpbml0aWFsX2JhbGFuY2UgPSAzIFsKICAgIChnb2dvcHJvdG8uY3VzdG9tdHlwZSkgPSAmcXVvdDtnaXRodWIuY29tL2Nvc21vcy9jb3Ntb3Mtc2RrL3R5cGVzLkludCZxdW90OywKICAgIChnb2dvcHJvdG8ubnVsbGFibGUpICAgPSBmYWxzZSwKICAgIChnb2dvcHJvdG8ubW9yZXRhZ3MpICAgPSAmcXVvdDt5YW1sOlwmcXVvdDtpbml0aWFsX2JhbGFuY2VcJnF1b3Q7JnF1b3Q7CiAgXTsKICBzdHJpbmcgc2hhcmVzX2RzdCA9IDQKICAgICAgWyhnb2dvcHJvdG8uY3VzdG9tdHlwZSkgPSAmcXVvdDtnaXRodWIuY29tL2Nvc21vcy9jb3Ntb3Mtc2RrL3R5cGVzLkRlYyZxdW90OywgKGdvZ29wcm90by5udWxsYWJsZSkgPSBmYWxzZV07Cn0KCi8vIFJlZGVsZWdhdGlvbiBjb250YWlucyB0aGUgbGlzdCBvZiBhIHBhcnRpY3VsYXIgZGVsZWdhdG9yJ3MgcmVkZWxlZ2F0aW5nIGJvbmRzCi8vIGZyb20gYSBwYXJ0aWN1bGFyIHNvdXJjZSB2YWxpZGF0b3IgdG8gYSBwYXJ0aWN1bGFyIGRlc3RpbmF0aW9uIHZhbGlkYXRvci4KbWVzc2FnZSBSZWRlbGVnYXRpb24gewogIG9wdGlvbiAoZ29nb3Byb3RvLmVxdWFsKSAgICAgICAgICAgID0gZmFsc2U7CiAgb3B0aW9uIChnb2dvcHJvdG8uZ29wcm90b19nZXR0ZXJzKSAgPSBmYWxzZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX3N0cmluZ2VyKSA9IGZhbHNlOwoKICBzdHJpbmcgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0b3JfYWRkcmVzcyAgICAgPSAxIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O2RlbGVnYXRvcl9hZGRyZXNzXCZxdW90OyZxdW90O107CiAgc3RyaW5nICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdG9yX3NyY19hZGRyZXNzID0gMiBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDt2YWxpZGF0b3Jfc3JjX2FkZHJlc3NcJnF1b3Q7JnF1b3Q7XTsKICBzdHJpbmcgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0b3JfZHN0X2FkZHJlc3MgPSAzIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O3ZhbGlkYXRvcl9kc3RfYWRkcmVzc1wmcXVvdDsmcXVvdDtdOwogIHJlcGVhdGVkIFJlZGVsZWdhdGlvbkVudHJ5IGVudHJpZXMgICAgICAgICAgICAgICA9IDQgWyhnb2dvcHJvdG8ubnVsbGFibGUpID0gZmFsc2VdOyAvLyByZWRlbGVnYXRpb24gZW50cmllcwp9"}})],1),e._v(" "),t("h2",{attrs:{id:"queues"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#queues"}},[e._v("#")]),e._v(" Queues")]),e._v(" "),t("p",[e._v("All queues objects are sorted by timestamp. The time used within any queue is\nfirst rounded to the nearest nanosecond then sorted. The sortable time format\nused is a slight modification of the RFC3339Nano and uses the the format string\n"),t("code",[e._v('"2006-01-02T15:04:05.000000000"')]),e._v(". Notably this format:")]),e._v(" "),t("ul",[t("li",[e._v("right pads all zeros")]),e._v(" "),t("li",[e._v("drops the time zone info (uses UTC)")])]),e._v(" "),t("p",[e._v("In all cases, the stored timestamp represents the maturation time of the queue\nelement.")]),e._v(" "),t("h3",{attrs:{id:"unbondingdelegationqueue"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#unbondingdelegationqueue"}},[e._v("#")]),e._v(" UnbondingDelegationQueue")]),e._v(" "),t("p",[e._v("For the purpose of tracking progress of unbonding delegations the unbonding\ndelegations queue is kept.")]),e._v(" "),t("ul",[t("li",[e._v("UnbondingDelegation: "),t("code",[e._v("0x41 | format(time) -> []DVPair")])])]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gRFZQYWlyIGlzIHN0cnVjdCB0aGF0IGp1c3QgaGFzIGEgZGVsZWdhdG9yLXZhbGlkYXRvciBwYWlyIHdpdGggbm8gb3RoZXIgZGF0YS4KLy8gSXQgaXMgaW50ZW5kZWQgdG8gYmUgdXNlZCBhcyBhIG1hcnNoYWxhYmxlIHBvaW50ZXIuIEZvciBleGFtcGxlLCBhIERWUGFpciBjYW4KLy8gYmUgdXNlZCB0byBjb25zdHJ1Y3QgdGhlIGtleSB0byBnZXR0aW5nIGFuIFVuYm9uZGluZ0RlbGVnYXRpb24gZnJvbSBzdGF0ZS4KbWVzc2FnZSBEVlBhaXIgewogIG9wdGlvbiAoZ29nb3Byb3RvLmVxdWFsKSAgICAgICAgICAgID0gZmFsc2U7CiAgb3B0aW9uIChnb2dvcHJvdG8uZ29wcm90b19nZXR0ZXJzKSAgPSBmYWxzZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX3N0cmluZ2VyKSA9IGZhbHNlOwoKICBzdHJpbmcgZGVsZWdhdG9yX2FkZHJlc3MgPSAxIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O2RlbGVnYXRvcl9hZGRyZXNzXCZxdW90OyZxdW90O107CiAgc3RyaW5nIHZhbGlkYXRvcl9hZGRyZXNzID0gMiBbKGdvZ29wcm90by5tb3JldGFncykgPSAmcXVvdDt5YW1sOlwmcXVvdDt2YWxpZGF0b3JfYWRkcmVzc1wmcXVvdDsmcXVvdDtdOwp9"}})],1),e._v(" "),t("h3",{attrs:{id:"redelegationqueue"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#redelegationqueue"}},[e._v("#")]),e._v(" RedelegationQueue")]),e._v(" "),t("p",[e._v("For the purpose of tracking progress of redelegations the redelegation queue is\nkept.")]),e._v(" "),t("ul",[t("li",[e._v("UnbondingDelegation: "),t("code",[e._v("0x42 | format(time) -> []DVVTriplet")])])]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gRFZWVHJpcGxldCBpcyBzdHJ1Y3QgdGhhdCBqdXN0IGhhcyBhIGRlbGVnYXRvci12YWxpZGF0b3ItdmFsaWRhdG9yIHRyaXBsZXQKLy8gd2l0aCBubyBvdGhlciBkYXRhLiBJdCBpcyBpbnRlbmRlZCB0byBiZSB1c2VkIGFzIGEgbWFyc2hhbGFibGUgcG9pbnRlci4gRm9yCi8vIGV4YW1wbGUsIGEgRFZWVHJpcGxldCBjYW4gYmUgdXNlZCB0byBjb25zdHJ1Y3QgdGhlIGtleSB0byBnZXR0aW5nIGEKLy8gUmVkZWxlZ2F0aW9uIGZyb20gc3RhdGUuCm1lc3NhZ2UgRFZWVHJpcGxldCB7CiAgb3B0aW9uIChnb2dvcHJvdG8uZXF1YWwpICAgICAgICAgICAgPSBmYWxzZTsKICBvcHRpb24gKGdvZ29wcm90by5nb3Byb3RvX2dldHRlcnMpICA9IGZhbHNlOwogIG9wdGlvbiAoZ29nb3Byb3RvLmdvcHJvdG9fc3RyaW5nZXIpID0gZmFsc2U7CgogIHN0cmluZyBkZWxlZ2F0b3JfYWRkcmVzcyAgICAgPSAxIFsoZ29nb3Byb3RvLm1vcmV0YWdzKSA9ICZxdW90O3lhbWw6XCZxdW90O2RlbGVnYXRvcl9hZGRyZXNzXCZxdW90OyZxdW90O107CiAgc3RyaW5nIHZhbGlkYXRvcl9zcmNfYWRkcmVzcyA9IDIgWyhnb2dvcHJvdG8ubW9yZXRhZ3MpID0gJnF1b3Q7eWFtbDpcJnF1b3Q7dmFsaWRhdG9yX3NyY19hZGRyZXNzXCZxdW90OyZxdW90O107CiAgc3RyaW5nIHZhbGlkYXRvcl9kc3RfYWRkcmVzcyA9IDMgWyhnb2dvcHJvdG8ubW9yZXRhZ3MpID0gJnF1b3Q7eWFtbDpcJnF1b3Q7dmFsaWRhdG9yX2RzdF9hZGRyZXNzXCZxdW90OyZxdW90O107Cn0="}})],1),e._v(" "),t("h3",{attrs:{id:"validatorqueue"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#validatorqueue"}},[e._v("#")]),e._v(" ValidatorQueue")]),e._v(" "),t("p",[e._v("For the purpose of tracking progress of unbonding validators the validator\nqueue is kept.")]),e._v(" "),t("ul",[t("li",[e._v("ValidatorQueueTime: "),t("code",[e._v("0x43 | format(time) -> []sdk.ValAddress")])])]),e._v(" "),t("p",[e._v("The stored object as each key is an array of validator operator addresses from\nwhich the validator object can be accessed. Typically it is expected that only\na single validator record will be associated with a given timestamp however it is possible\nthat multiple validators exist in the queue at the same location.")]),e._v(" "),t("h2",{attrs:{id:"historicalinfo"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#historicalinfo"}},[e._v("#")]),e._v(" HistoricalInfo")]),e._v(" "),t("p",[e._v("HistoricalInfo objects are stored and pruned at each block such that the staking keeper persists\nthe "),t("code",[e._v("n")]),e._v(" most recent historical info defined by staking module parameter: "),t("code",[e._v("HistoricalEntries")]),e._v(".")]),e._v(" "),t("p",[t("tm-code-block",{staticClass:"codeblock",attrs:{language:"false",base64:"Ly8gSGlzdG9yaWNhbEluZm8gY29udGFpbnMgaGVhZGVyIGFuZCB2YWxpZGF0b3IgaW5mb3JtYXRpb24gZm9yIGEgZ2l2ZW4gYmxvY2suCi8vIEl0IGlzIHN0b3JlZCBhcyBwYXJ0IG9mIHN0YWtpbmcgbW9kdWxlJ3Mgc3RhdGUsIHdoaWNoIHBlcnNpc3RzIHRoZSBgbmAgbW9zdAovLyByZWNlbnQgSGlzdG9yaWNhbEluZm8KLy8gKGBuYCBpcyBzZXQgYnkgdGhlIHN0YWtpbmcgbW9kdWxlJ3MgYGhpc3RvcmljYWxfZW50cmllc2AgcGFyYW1ldGVyKS4KbWVzc2FnZSBIaXN0b3JpY2FsSW5mbyB7CiAgdGVuZGVybWludC50eXBlcy5IZWFkZXIgaGVhZGVyID0gMSBbKGdvZ29wcm90by5udWxsYWJsZSkgPSBmYWxzZV07CiAgcmVwZWF0ZWQgVmFsaWRhdG9yICAgICAgdmFsc2V0ID0gMiBbKGdvZ29wcm90by5udWxsYWJsZSkgPSBmYWxzZV07Cn0="}})],1),e._v(" "),t("p",[e._v("At each BeginBlock, the staking keeper will persist the current Header and the Validators that committed\nthe current block in a "),t("code",[e._v("HistoricalInfo")]),e._v(" object. The Validators are sorted on their address to ensure that\nthey are in a determisnistic order.\nThe oldest HistoricalEntries will be pruned to ensure that there only exist the parameter-defined number of\nhistorical entries.")])])}),[],!1,null,null,null);d.default=n.exports}}]);