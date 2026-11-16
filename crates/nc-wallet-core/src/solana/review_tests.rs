//! What the summary says about the user's own accounts, and when it may be
//! reassuring.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::message::*;
use super::summary::*;

const USER: Pubkey = [7; 32];
const OTHER: Pubkey = [8; 32];

fn tx(instructions: &[Instruction]) -> Vec<u8> {
    let message = compile(&USER, instructions, &[1; 32]).unwrap();
    transaction(&vec![[0; 64]; usize::from(message[0])], &message)
}

fn read(instructions: &[Instruction]) -> TransactionSummary {
    summarize_transaction_for(&tx(instructions), &[], &USER).unwrap()
}

fn system(tag: u32, parts: &[&[u8]], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = tag.to_le_bytes().to_vec();
    for part in parts {
        data.extend_from_slice(part);
    }
    Instruction { program: SYSTEM_PROGRAM, accounts, data }
}

fn token(data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    Instruction { program: TOKEN_PROGRAM, accounts, data: data.to_vec() }
}

#[test]
fn assigning_the_users_account_is_dangerous_and_moves_funds() {
    let summary = read(&[system(1, &[&[9; 32]], vec![AccountMeta::writable(USER, true)])]);
    assert_eq!(
        summary.instructions[0],
        InstructionSummary::SystemAssign { account: USER, owner: [9; 32], base: None }
    );
    assert_eq!(summary.reviews[0].danger, Some(Danger::AssignOwner));
    assert!(summary.reviews[0].user_signer && summary.reviews[0].user_writable);
    assert!(summary.fully_understood, "it is decoded");
    assert!(summary.may_move_user_funds, "but giving the account away is not 'nothing is sent'");
    assert_eq!(summary.reviews[0].program_name, Some("System"));
    // Assigning somebody else's account is not a danger to this user.
    let other = summarize_transaction_for(
        &tx(&[
            system(1, &[&[9; 32]], vec![AccountMeta::writable(OTHER, true)]),
            system(
                2,
                &[&1_u64.to_le_bytes()],
                vec![AccountMeta::writable(OTHER, true), AccountMeta::writable([1; 32], false)],
            ),
        ]),
        &[],
        &USER,
    )
    .unwrap();
    assert_eq!(other.reviews[0].danger, None);
}

#[test]
fn the_system_instructions_are_decoded() {
    let two = |a: u8| 5_u64.to_le_bytes().into_iter().chain([a]).collect::<Vec<_>>();
    let _ = two;
    let seed = |s: &[u8]| [&(s.len() as u64).to_le_bytes()[..], s].concat();
    let summary = read(&[
        system(
            0,
            &[&10_u64.to_le_bytes(), &165_u64.to_le_bytes(), &TOKEN_PROGRAM],
            vec![AccountMeta::writable(USER, true), AccountMeta::writable([2; 32], true)],
        ),
        system(
            3,
            &[&[3; 32], &seed(b"seed"), &11_u64.to_le_bytes(), &0_u64.to_le_bytes(), &[0; 32]],
            vec![
                AccountMeta::writable(USER, true),
                AccountMeta::writable([4; 32], false),
                AccountMeta::readonly([3; 32], true),
            ],
        ),
        system(
            11,
            &[&12_u64.to_le_bytes(), &seed(b"s"), &SYSTEM_PROGRAM],
            vec![
                AccountMeta::writable([5; 32], false),
                AccountMeta::readonly(USER, true),
                AccountMeta::writable([6; 32], false),
            ],
        ),
        system(8, &[&99_u64.to_le_bytes()], vec![AccountMeta::writable(USER, true)]),
    ]);
    assert!(matches!(
        summary.instructions[0],
        InstructionSummary::SystemCreateAccount { lamports: 10, space: 165, owner, .. } if owner == TOKEN_PROGRAM
    ));
    assert!(matches!(&summary.instructions[1],
        InstructionSummary::SystemCreateAccount { seed: Some(s), lamports: 11, .. } if s == "seed"));
    assert!(matches!(&summary.instructions[2],
        InstructionSummary::SystemTransferWithSeed { lamports: 12, from, base, .. } if *from == [5; 32] && *base == USER));
    assert_eq!(
        summary.instructions[3],
        InstructionSummary::SystemAllocate { account: USER, space: 99 }
    );
    assert!(summary.reviews[0].moves_user_funds && summary.reviews[2].moves_user_funds);
    assert_eq!(summary.reviews[3].danger, Some(Danger::Allocate));
    assert!(summary.fully_understood);
}

#[test]
fn a_durable_nonce_is_flagged() {
    let advance = system(
        4,
        &[],
        vec![
            AccountMeta::writable([5; 32], false),
            AccountMeta::readonly([6; 32], false),
            AccountMeta::readonly(USER, true),
        ],
    );
    let summary = read(&[advance, system_transfer(USER, OTHER, 1)]);
    assert!(summary.durable_nonce);
    assert_eq!(summary.reviews[0].danger, Some(Danger::DurableNonce));
    assert!(summary.may_move_user_funds);
    // Withdrawing from, and handing over, a nonce account are read too.
    let summary = read(&[
        system(
            5,
            &[&3_u64.to_le_bytes()],
            vec![
                AccountMeta::writable([5; 32], false),
                AccountMeta::writable(OTHER, false),
                AccountMeta::readonly([6; 32], false),
                AccountMeta::readonly([6; 32], false),
                AccountMeta::readonly(USER, true),
            ],
        ),
        system(
            7,
            &[&[1; 32]],
            vec![AccountMeta::writable([5; 32], false), AccountMeta::readonly(USER, true)],
        ),
    ]);
    assert!(matches!(
        summary.instructions[0],
        InstructionSummary::SystemWithdrawNonce { lamports: 3, .. }
    ));
    assert!(matches!(summary.instructions[1], InstructionSummary::SystemAuthorizeNonce { .. }));
    assert_eq!(summary.reviews[1].danger, Some(Danger::NonceAuthority));
    assert!(!summary.durable_nonce);
}

#[test]
fn the_token_instructions_are_decoded_and_marked() {
    let account = [20; 32];
    let mint = [21; 32];
    let set_authority: Vec<u8> = [6, 2, 1].into_iter().chain([9; 32]).collect();
    let summary = read(&[
        token(
            &set_authority,
            vec![AccountMeta::writable(account, false), AccountMeta::readonly(USER, true)],
        ),
        token(
            &[9],
            vec![
                AccountMeta::writable(account, false),
                AccountMeta::writable(OTHER, false),
                AccountMeta::readonly(USER, true),
            ],
        ),
        token(
            &[15, 5, 0, 0, 0, 0, 0, 0, 0, 6],
            vec![
                AccountMeta::writable(account, false),
                AccountMeta::writable(mint, false),
                AccountMeta::readonly(USER, true),
            ],
        ),
        token(&[5], vec![AccountMeta::writable(account, false), AccountMeta::readonly(USER, true)]),
    ]);
    assert!(matches!(&summary.instructions[0],
        InstructionSummary::SplSetAuthority { authority_type: 2, new_authority: Some(n), .. } if *n == [9; 32]));
    assert!(matches!(summary.instructions[1], InstructionSummary::SplCloseAccount { .. }));
    assert!(matches!(
        summary.instructions[2],
        InstructionSummary::SplBurn { amount: 5, decimals: Some(6), .. }
    ));
    assert!(matches!(summary.instructions[3], InstructionSummary::SplRevoke { .. }));
    let dangers: Vec<_> = summary.reviews.iter().map(|r| r.danger).collect();
    assert_eq!(dangers, [Some(Danger::SetAuthority), Some(Danger::CloseAccount), None, None]);
    assert!(summary.fully_understood && summary.may_move_user_funds);
    // The account the user signs for is known to be theirs.
    assert!(summary.user_token_accounts.contains(&account));
    assert_eq!(summary.reviews[0].program_name, Some("Token"));
}

#[test]
fn an_approval_is_a_danger_even_when_it_is_small() {
    let mut data = vec![4u8];
    data.extend_from_slice(&5_u64.to_le_bytes());
    let summary = read(&[token(
        &data,
        vec![
            AccountMeta::writable([20; 32], false),
            AccountMeta::readonly(OTHER, false),
            AccountMeta::readonly(USER, true),
        ],
    )]);
    assert_eq!(summary.reviews[0].danger, Some(Danger::Approve));
    assert!(summary.may_move_user_funds);
}

#[test]
fn a_memo_is_text_and_hidden_characters_are_shown() {
    let memo = |text: &str| Instruction {
        program: MEMO_PROGRAM,
        accounts: vec![AccountMeta::readonly(USER, true)],
        data: text.as_bytes().to_vec(),
    };
    let summary = read(&[memo("order 42"), memo("pay \u{202E}now")]);
    assert!(
        matches!(&summary.instructions[0], InstructionSummary::Memo { text: Some(t), .. } if t == "order 42")
    );
    let InstructionSummary::Memo { text, escaped, .. } = &summary.instructions[1] else { panic!() };
    assert_eq!(text, &None);
    assert_eq!(escaped.as_deref(), Some("pay <U+202E>now"));
    assert!(summary.fully_understood && !summary.may_move_user_funds, "a memo moves nothing");
    assert_eq!(summary.reviews[0].program_name, Some("Memo"));
}

#[test]
fn only_a_whole_understood_transaction_that_moves_nothing_is_reassuring() {
    let unknown = |accounts: Vec<AccountMeta>| Instruction {
        program: [66; 32],
        accounts,
        data: vec![1, 2, 3],
    };
    // Unknown, and the user is a signer: understood = false, moves = true.
    let summary = read(&[unknown(vec![AccountMeta::readonly(USER, true)])]);
    assert!(!summary.fully_understood && summary.may_move_user_funds);
    assert!(summary.reviews[0].user_signer);
    // Unknown, and the user is not in it (fee payer only): not understood, but it
    // does not use the user's accounts.
    let summary = read(&[unknown(vec![AccountMeta::writable([30; 32], false)])]);
    assert!(!summary.fully_understood && !summary.may_move_user_funds);
    assert!(!summary.reviews[0].user_signer && !summary.reviews[0].user_writable);
    // Unknown, with the user's associated token account writable in it: the
    // account is known from the mint another instruction names.
    let mint = [31; 32];
    let ata = associated_token_account(&USER, &mint).unwrap();
    let summary = read(&[
        create_associated_token_account_idempotent(OTHER, ata, USER, mint),
        unknown(vec![AccountMeta::writable(ata, false)]),
    ]);
    assert!(summary.reviews[1].user_writable && summary.reviews[1].moves_user_funds);
    assert_eq!(summary.reviews[1].user_accounts, [ata]);
    // Compute budget alone: understood and moves nothing.
    let summary = read(&[set_compute_unit_limit(1000), set_compute_unit_price(1)]);
    assert!(summary.fully_understood && !summary.may_move_user_funds && !summary.durable_nonce);
    assert_eq!(summary.reviews[0].program_name, Some("Compute Budget"));
    // Without a user, nothing is claimed about one.
    let plain =
        summarize_transaction(&tx(&[unknown(vec![AccountMeta::readonly(USER, true)])]), &[])
            .unwrap();
    assert!(!plain.reviews[0].user_signer && plain.user.is_none());
}

#[test]
fn a_swap_like_transfer_is_known_to_move_funds_but_not_to_be_all() {
    let summary = read(&[system_transfer(USER, OTHER, 5)]);
    assert!(summary.fully_understood && summary.may_move_user_funds);
    assert_eq!(program_name(&TOKEN_2022_PROGRAM), Some("Token-2022"));
    assert_eq!(program_name(&ASSOCIATED_TOKEN_PROGRAM), Some("Associated Token"));
    assert_eq!(program_name(&[1; 32]), None);
}
