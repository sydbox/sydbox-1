/*
 * libsyd/about.c
 *
 * libsyd Tarot Draw Interface
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <sys/random.h>
#include <syd/syd.h>

#define TAROT_MAX 78
static const char *TAROT_CARDS[TAROT_MAX];
static const char *TAROT_SIDES[TAROT_MAX][2];

static bool syd_tarot_init;

int syd_tarot_draw(char **tarot_card)
{
	if (!syd_tarot_init) {
		uint64_t seed;
		for (;;) {
			if (getrandom(&seed, sizeof(uint64_t),
				      GRND_RANDOM) < 0) {
				if (errno == EINTR)
					continue;
				return -errno;
			}
			break;
		}
		srand(seed);
		syd_tarot_init = true;
	}

	const char *card;
	const char *side;
	size_t pick = rand() % TAROT_MAX;
	bool revers = rand() % 2 == 1;
	card = TAROT_CARDS[pick];
	side = (revers)
		? TAROT_SIDES[pick][0]
		: TAROT_SIDES[pick][1];

	char *p;
	if (asprintf(&p, "%s %s- %s\n",
		     card,
		     revers ? "(Reversed) " : "",
		     side) < 0)
		return -errno;

	*tarot_card = p;
	return 0;
}

static const char *TAROT_CARDS[TAROT_MAX] = {
  /* Major Arcana */
  "The Fool",
  "The Magician",
  "The High Priestess",
  "The Empress",
  "The Emperor",
  "The Heirophant",
  "The Lovers",
  "The Chariot",
  "Strength",
  "The Hermit",
  "Wheel of Fortune",
  "Justice",
  "The Hanged Man",
  "Death",
  "Temperance",
  "The Devil",
  "The Tower",
  "The Star",
  "The Moon",
  "The Sun",
  "Judgment",
  "The World",

  /* Cups */
  "The King of Cups",
  "The Queen of Cups",
  "The Knight of Cups",
  "The Page of Cups",
  "The Ten of Cups",
  "The Nine of Cups",
  "The Eight of Cups",
  "The Seven of Cups",
  "The Six of Cups",
  "The Five of Cups",
  "The Four of Cups",
  "The Three of Cups",
  "The Two of Cups",
  "The Ace of Cups",

  /* Swords */
  "The King of Swords",
  "The Queen of Swords",
  "The Knight of Swords",
  "The Page of Swords",
  "The Ten of Swords",
  "The Nine of Swords",
  "The Eight of Swords",
  "The Seven of Swords",
  "The Six of Swords",
  "The Five of Swords",
  "The Four of Swords",
  "The Three of Swords",
  "The Two of Swords",
  "The Ace of Swords",

  /* Wands */
  "The King of Wands",
  "The Queen of Wands",
  "The Knight of Wands",
  "The Page of Wands",
  "The Ten of Wands",
  "The Nine of Wands",
  "The Eight of Wands",
  "The Seven of Wands",
  "The Six of Wands",
  "The Five of Wands",
  "The Four of Wands",
  "The Three of Wands",
  "The Two of Wands",
  "The Ace of Wands",

  /* Pentacles */
  "The King of Pentacles",
  "The Queen of Pentacles",
  "The Knight of Pentacles",
  "The Page of Pentacles",
  "The Ten of Pentacles",
  "The Nine of Pentacles",
  "The Eight of Pentacles",
  "The Seven of Pentacles",
  "The Six of Pentacles",
  "The Five of Pentacles",
  "The Four of Pentacles",
  "The Three of Pentacles",
  "The Two of Pentacles",
  "The Ace of Pentacles",
};

static const char *TAROT_SIDES[TAROT_MAX][2] = {
  /* Major Arcana */
  {"innocence, new beginnings, free spirit",
   "recklessness, taken advantage of, inconsideration"},
  {"willpower, desire, creation, manifestation",
   "trickery, illusions, out of touch"},
  {"intuitive, unconscious, inner voice",
   "lack of center, lost inner voice, repressed feelings"},
  {"motherhood, fertility, nature",
   "dependence, smothering, emptiness, nosiness"},
  {"authority, structure, control, fatherhood",
   "tyranny, rigidity, coldness"},
  {"tradition, conformity, morality, ethics",
   "rebellion, subversiveness, new approaches"},
  {"partnerships, duality, union",
   "loss of balance, one-sidedness, disharmony"},
  {"direction, control, willpower",
   "lack of control, lack of direction, aggression"},
  {"inner strength, bravery, compassion, focus",
   "self doubt, weakness, insecurity"},
  {"contemplation, search for truth, inner guidance",
   "loneliness, isolation, lost your way"},
  {"change, cycles, inevitable fate",
   "no control, clinging to control, bad luck"},
  {"cause and effect, clarity, truth",
   "dishonesty, unaccountability, unfairness"},
  {"sacrifice, release, martyrdom",
   "stalling, needless sacrifice, fear of sacrifice"},
  {"end of cycle, beginnings, change, metamorphosis",
   "fear of change, holding on, stagnation, decay"},
  {"middle path, patience, finding meaning",
   "extremes, excess, lack of balance"},
  {"addiction, materialism, playfulness",
   "freedom, release, restoring control"},
  {"sudden upheaval, broken pride, disaster",
   "disaster avoided, delayed disaster, fear of suffering"},
  {"hope, faith, rejuvenation",
   "faithlessness, discouragement, insecurity"},
  {"unconscious, illusions, intuition",
   "confusion, fear, misinterpretation"},
  {"joy, success, celebration, positivity",
   "negativity, depression, sadness"},
  {"reflection, reckoning, awakening",
   "lack of self awareness, doubt, self loathing"},
  {"fulfillment, harmony, completion",
   "incompletion, no closure"},

  /* Cups */
  {"compassion, control, balance",
   "coldness, moodiness, bad advice"},
  {"compassion, calm, comfort",
   "martyrdom, insecurity, dependence"},
  {"following the heart, idealist, romantic",
   "moodiness, disappointment"},
  {"happy surprise, dreamer, sensitivity",
   "emotional immaturity, insecurity, disappointment"},
  {"inner happiness, fulfillment, dreams coming true",
   "shattered dreams, broken family, domestic disharmony"},
  {"satisfaction, emotional stability, luxury",
   "lack of inner joy, smugness, dissatisfaction"},
  {"walking away, disillusionment, leaving behind",
   "avoidance, fear of change, fear of loss"},
  {"searching for purpose, choices, daydreaming",
   "lack of purpose, diversion, confusion"},
  {"familiarity, happy memories, healing",
   "moving forward, leaving home, independence"},
  {"loss, grief, self-pity",
   "acceptance, moving on, finding peace"},
  {"apathy, contemplation, disconnectedness",
   "sudden awareness, choosing happiness, acceptance"},
  {"friendship, community, happiness",
   "overindulgence, gossip, isolation"},
  {"unity, partnership, connection",
   "imbalance, broken communication, tension"},
  {"new feelings, spirituality, intuition",
   "emotional loss, blocked creativity, emptiness"},

  /* Swords */
  {"head over heart, discipline, truth",
   "manipulative, cruel, weakness"},
  {"complexity, perceptiveness, clear mindedness",
   "cold hearted, cruel, bitterness"},
  {"action, impulsiveness, defending beliefs",
   "no direction, disregard for consequences, unpredictability"},
  {"curiosity, restlessness, mental energy",
   "deception, manipulation, all talk"},
  {"failure, collapse, defeat",
   "can't get worse, only upwards, inevitable end"},
  {"anxiety, hopelessness, trauma",
   "hope, reaching out, despair"},
  {"imprisonment, entrapment, self-victimization",
   "self acceptance, new perspective, freedom"},
  {"deception, trickery, tactics and strategy",
   "coming clean, rethinking approach, deception"},
  {"transition, leaving behind, moving on",
   "emotional baggage, unresolved issues, resisting transition"},
  {"unbridled ambition, win at all costs, sneakiness",
   "lingering resentment, desire to reconcile, forgiveness"},
  {"rest, restoration, contemplation",
   "restlessness, burnout, stress"},
  {"heartbreak, suffering, grief",
   "recovery, forgiveness, moving on"},
  {"difficult choices, indecision, stalemate",
   "lesser of two evils, no right choice, confusion"},
  {"breakthrough, clarity, sharp mind",
   "confusion, brutality, chaos"},

  /* Wands */
  {"big picture, leader, overcoming challenges",
   "impulsive, overbearing, unachievable expectations"},
  {"courage, determination, joy",
   "selfishness, jealousy, insecurities"},
  {"action, adventure, fearlessness",
   "anger, impulsiveness, recklessness"},
  {"exploration, excitement, freedom",
   "lack of direction, procrastination, creating conflict"},
  {"accomplishment, responsibility, burden",
   "inability to delegate, overstressed, burnt out"},
  {"resilience, grit, last stand",
   "exhaustion, fatigue, questioning motivations"},
  {"rapid action, movement, quick decisions",
   "panic, waiting, slowdown"},
  {"perseverance, defensive, maintaining control",
   "give up, destroyed confidence, overwhelmed"},
  {"victory, success, public reward",
   "excess pride, lack of recognition, punishment"},
  {"competition, rivalry, conflict",
   "avoiding conflict, respecting differences"},
  {"community, home, celebration",
   "lack of support, transience, home conflicts"},
  {"looking ahead, expansion, rapid growth",
   "obstacles, delays, frustration"},
  {"planning, making decisions, leaving home",
   "fear of change, playing safe, bad planning"},
  {"creation, willpower, inspiration, desire",
   "lack of energy, lack of passion, boredom"},

  /* Pentacles */
  {"abundance, prosperity, security",
   "greed, indulgence, sensuality"},
  {"practicality, creature comforts, financial security",
   "self-centeredness, jealousy, smothering"},
  {"efficiency, hard work, responsibility",
   "laziness, obsessiveness, work without reward"},
  {"ambition, desire, diligence",
   "lack of commitment, greediness, laziness"},
  {"legacy, culmination, inheritance",
   "fleeting success, lack of stability, lack of resources"},
  {"fruits of labor, rewards, luxury",
   "reckless spending, living beyond means, false success"},
  {"apprenticeship, passion, high standards",
   "lack of passion, uninspired, no motivation"},
  {"hard work, perseverance, diligence",
   "work without results, distractions, lack of rewards"},
  {"charity, generosity, sharing",
   "strings attached, stinginess, power and domination"},
  {"need, poverty, insecurity",
   "recovery, charity, improvement"},
  {"conservation, frugality, security",
   "greediness, stinginess, possessiveness"},
  {"teamwork, collaboration, building",
   "lack of teamwork, disorganized, group conflict"},
  {"balancing decisions, priorities, adapting to change",
   "loss of balance, disorganized, overwhelmed"},
  {"opportunity, prosperity, new venture",
   "lost opportunity, missed chance, bad investment"},
};
