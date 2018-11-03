//
// Created by Dallas Johnson on 23/10/2018.
//

#include "dacmultisigs.hpp"

void dacmultisigs::stproposal(string transactionid, name proposer, name proposalname) {
    require_auth(proposer);

    proposals_table proposals(_self, _self);

    proposals.emplace(_self, [&](proposal &p) {
        p.proposalid = proposals.available_primary_key();
        p.transactionid = transactionid;
        p.proposer = proposer;
        p.proposalname = proposalname;
    });
}

    void dacmultisigs::delproposal(uint64_t proposalid) {
        proposals_table proposals(_self, _self);
        const auto &prop = proposals.get(proposalid, "ERR::delproposal_proposal_not_found::Proposal with id could not be found.");
        proposals.erase(prop);
    }


    template <typename T>
    void cleanTable(uint64_t code, uint64_t account){
        T db(code, account);
        while(db.begin() != db.end()){
            auto itr = --db.end();
            db.erase(itr);
        }
    }

    void dacmultisigs::clear() {
        cleanTable<proposals_table>(_self, _self);
    }

EOSIO_ABI( dacmultisigs,
        (stproposal)
        (delproposal)
        (clear)
        )
