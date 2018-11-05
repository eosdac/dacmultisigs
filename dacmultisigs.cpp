//
// Created by Dallas Johnson on 23/10/2018.
//

#include "dacmultisigs.hpp"
#include <eosiolib/action.hpp>
#include <eosiolib/permission.hpp>
#include <eosiolib/crypto.h>

void dacmultisigs::stproposal(account_name proposer, name proposalname, checksum256 transactionid, string metadata) {
    require_auth( name{N(dacauthority)} );

    proposals_table proposals(_self, proposer);

    proposals.emplace(_self, [&](storedproposal &p) {
        p.proposalname = proposalname;
        p.transactionid = transactionid;
    });
}

void dacmultisigs::stinproposal() {

    require_auth(name{N(dacauthority)});

    constexpr size_t max_stack_buffer_size = 512;
    size_t action_size = action_data_size();
    char* action_buffer = (char*)( max_stack_buffer_size < action_size ? malloc(action_size) : alloca(action_size) );
    read_action_data( action_buffer, action_size );


    auto size = transaction_size();
    char* buffer = (char*)( 512 < size ? malloc(size) : alloca(size) );
    uint32_t read = read_transaction( buffer, size );
    eosio_assert( size == read, "read_transaction failed");

    checksum256 trx_id;
    sha256(buffer, read, &trx_id);

    transaction trx = eosio::unpack<transaction>(buffer, size);

    string metadata;
    account_name proposer;
    account_name proposal_name;

    datastream<const char*> ds( action_buffer, action_size );
//    ds >> metadata;

    size_t msig_startpos = ds.tellp();

    ds >> proposer >> proposal_name;
    print(" details about the actions:::");
    print(" meta: ", metadata.c_str());
    print(" proposer: ", name{proposer}.to_string().c_str() );
    print(" proposal: ", name{proposal_name}.to_string().c_str());

    vector<char> msig_buffer = bytes(buffer + msig_startpos, buffer + size);

    eosio::print("proposer: ", name{proposer});

    action(
            permission_level(N(dacauthority), N(active)),
            N(eosio.msig),
            N(propose),
            msig_buffer
    ).send();

    proposals_table proposals(_self, proposer);

    proposals.emplace(proposer, [&](storedproposal &p) {
        p.proposalname = proposal_name;
        p.transactionid = trx_id;
    });
}

void dacmultisigs::approve( account_name proposer, name proposal_name, permission_level level ){
    require_auth(level.actor);
    action(
            level,
            N(eosio.msig),
            N(approve),
            std::make_tuple(proposer, proposal_name, level)
    ).send();
}

void dacmultisigs::unapprove( account_name proposer, name proposal_name, permission_level level ){
    require_auth(level.actor);
    // forward to multisig contract
    action(
            level,
            N(eosio.msig),
            N(unapprove),
            std::make_tuple(proposer, proposal_name, level)
    ).send();
}

void dacmultisigs::cancel( account_name proposer, name proposal_name, account_name canceler ){
    require_auth(canceler);
    // forward to multisig contract
    action(
            permission_level{ canceler, N(active) },
            N(eosio.msig),
            N(cancel),
            std::make_tuple(proposer, proposal_name, canceler)
    ).send();

    //Clean up after canceling the proposal in the multisig contract
    proposals_table proposals(_self, proposer);
    auto& proposal_to_erase = proposals.get(proposal_name, "Proposal not found");
    proposals.erase(proposal_to_erase);
}

void dacmultisigs::exec( account_name proposer, name proposal_name, account_name executer ) {
    require_auth(executer);

    // forward to multisig contract
    action(
            permission_level{ executer, N(active) },
            N(eosio.msig),
            N(exec),
            std::make_tuple(proposer, proposal_name, executer)
    ).send();

    //Clean up after executing the proposal in the multisig contract
    proposals_table proposals(_self, proposer);
    auto& proposal_to_erase = proposals.get(proposal_name, "Proposal not found");
    proposals.erase(proposal_to_erase);
}

EOSIO_ABI(dacmultisigs,
          (stproposal)
                  (stinproposal)
                  (cancel)
                  (approve)
                  (unapprove)
                  (exec)
)
