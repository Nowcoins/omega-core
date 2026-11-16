//! The backup quiz: three questions about the phrase being made.

use nc_wallet_core::wordlist;

use crate::error::SessionError;

/// How many questions the backup check asks, and how many choices each has.
const QUIZ_QUESTIONS: usize = 3;
const QUIZ_CHOICES: usize = 6;

pub(crate) struct Quiz {
    /// 1-based positions, ascending.
    pub(crate) positions: Vec<usize>,
    pub(crate) choices: Vec<Vec<String>>,
    pub(crate) answered: Vec<bool>,
}

/// A number below `bound` from the system's randomness, without bias.
pub(crate) fn random_below(bound: usize) -> Result<usize, SessionError> {
    debug_assert!(bound > 0 && u32::try_from(bound).is_ok());
    let bound = u32::try_from(bound).map_err(|_| SessionError::Unavailable)?;
    // Reject the top of the range that does not fill a whole multiple of `bound`.
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).map_err(|_| SessionError::Unavailable)?;
        let n = u32::from_le_bytes(bytes);
        if n < limit {
            return Ok(usize::try_from(n % bound).unwrap_or(0));
        }
    }
}

pub(crate) fn shuffle<T>(items: &mut [T]) -> Result<(), SessionError> {
    for i in (1..items.len()).rev() {
        items.swap(i, random_below(i + 1)?);
    }
    Ok(())
}

/// Three distinct positions of the phrase, in order, each with the right word
/// among five that are not in the phrase at all. The app cannot tell which
/// choice is right without knowing the phrase.
pub(crate) fn make_quiz(words: &[String]) -> Result<Quiz, SessionError> {
    let mut order: Vec<usize> = (1..=words.len()).collect();
    shuffle(&mut order)?;
    let mut positions: Vec<usize> = order.into_iter().take(QUIZ_QUESTIONS).collect();
    positions.sort_unstable();

    let mut choices = Vec::with_capacity(positions.len());
    for position in &positions {
        choices.push(choices_for(words, *position)?);
    }
    let answered = vec![false; positions.len()];
    Ok(Quiz { positions, choices, answered })
}

/// The right word of `position` among five that are not in the phrase, shuffled.
fn choices_for(words: &[String], position: usize) -> Result<Vec<String>, SessionError> {
    let list = wordlist::all();
    let mut options = vec![words[position - 1].clone()];
    while options.len() < QUIZ_CHOICES {
        let candidate = list[random_below(list.len())?];
        if !words.iter().any(|w| w == candidate) && !options.iter().any(|o| o == candidate) {
            options.push(candidate.to_owned());
        }
    }
    shuffle(&mut options)?;
    Ok(options)
}

impl Quiz {
    /// After a wrong answer to the question at `position`: the question is drawn
    /// again, at **another** position of the phrase and with new decoys.
    ///
    /// Without this a wrong answer costs nothing and the quiz can be passed by
    /// trying the six choices in turn, never having seen the phrase. Now what a
    /// wrong answer rules out is gone: the next try is at a different word and
    /// among different decoys, a one-in-six guess again. The other questions are
    /// left as they are, answered or not, and the redrawn one keeps its place in the list (so an app
    /// that walks the list by index goes on at the same index; the positions are then no longer
    /// ascending, which is only how they are first asked).
    pub(crate) fn redraw(&mut self, words: &[String], position: usize) -> Result<(), SessionError> {
        let Some(slot) = self.positions.iter().position(|p| *p == position) else {
            return Ok(());
        };
        let free: Vec<usize> = (1..=words.len()).filter(|p| !self.positions.contains(p)).collect();
        if free.is_empty() {
            return Ok(());
        }
        let new_position = free[random_below(free.len())?];
        self.positions[slot] = new_position;
        self.choices[slot] = choices_for(words, new_position)?;
        self.answered[slot] = false;
        Ok(())
    }
}
