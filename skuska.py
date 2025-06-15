import tkinter as tk
import itertools
import re


### FUNKCIE PRE LOGIKU PROGRAMU ###

def show_frame(frame, clear_inputs=None):
    """Zobrazí daný rám a vymaže vstupné polia, ak sú zadané."""
    if clear_inputs:
        for entry in clear_inputs:
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
            elif isinstance(entry, tk.Text):
                entry.delete("1.0", tk.END)
    frame.tkraise()


def process_rules(rules_input):
    """
    Spracuje vstupné pravidlá a vráti ich ako slovník: neterminál -> zoznam produkcií.
    Každý riadok by mal byť vo formáte: S->aAB | b.
    Pravidlo "()" sa interpretuje ako prázdny reťazec (ε).
    """
    rules = {}
    for rule in rules_input:
        if "->" in rule:
            left, right = rule.split("->")
            left = left.strip()
            right = [r.strip() for r in right.split("|")]
            rules[left] = ["" if r == "()" else r for r in right]
    return rules


def find_simple_rules(grammar):
    """Nájde jednoduché pravidlá A -> B, kde B je neterminál (jedno písmeno)."""
    simple_rules = {}
    for A, productions in grammar.items():
        for prod in productions:
            if len(prod) == 1 and prod.isupper():
                simple_rules.setdefault(A, []).append(prod)
    return simple_rules


def remove_simple_rules(grammar, simple_rules):
    """
    Odstráni jednoduché pravidlá A->B a pridá nové podľa pravidla:
    ak A->B a B->γ, tak A->γ.
    """
    new_grammar = {key: set(value) for key, value in grammar.items()}
    changed = True
    while changed:
        changed = False
        for A, B_list in simple_rules.items():
            for B in B_list:
                if B in grammar:
                    for prod in grammar[B]:
                        if prod not in new_grammar[A]:
                            new_grammar[A].add(prod)
                            changed = True
        simple_rules = find_simple_rules(new_grammar)
    for A in list(new_grammar.keys()):
        new_grammar[A] = {p for p in new_grammar[A] if not (len(p) == 1 and p.isupper())}
    # Prekonvertujeme sety na listy
    final_grammar = {A: list(v) for A, v in new_grammar.items()}
    return final_grammar


def canonical_form(prod):
    """
    Normalizuje produkciu: nahradí každý neterminál (veľké písmeno s voliteľným apostrofom)
    jednotným symbolom "N". Terminály necháva nezmenené.
    """
    return re.sub(r"[A-Z](')?", "N", prod)


def merge_equivalent_non_terminals_once(grammar, original_nonterminals):
    """
    Jedna iterácia zlúčenia ekvivalentných neterminálov podľa canonical formy.
    """
    reverse_grammar = {}
    for nt, productions in grammar.items():
        canon_prods = sorted(canonical_form(p) for p in productions)
        key = tuple(canon_prods)
        reverse_grammar.setdefault(key, []).append(nt)
    merged_grammar = dict(grammar)
    changed = False
    for nts in reverse_grammar.values():
        if len(nts) > 1:
            candidates = [nt for nt in nts if nt in original_nonterminals]
            winner = candidates[0] if candidates else nts[0]
            for nt in nts:
                if nt == winner:
                    continue
                if nt in merged_grammar:
                    del merged_grammar[nt]
                for A in list(merged_grammar.keys()):
                    new_prods = []
                    for p in merged_grammar[A]:
                        new_prods.append(p.replace(nt, winner))
                    merged_grammar[A] = new_prods
            changed = True
    return merged_grammar, changed


def merge_equivalent_non_terminals_fixpoint(grammar, original_nonterminals):
    """
    Opakovane volá merge_equivalent_non_terminals_once, kým sa nedosiahne fixpoint.
    """
    changed = True
    current = grammar
    while changed:
        new_grammar, changed = merge_equivalent_non_terminals_once(current, original_nonterminals)
        current = new_grammar
    return current


def find_epsilon_producing(grammar, non_terminals):
    """
    Nájde všetky neterminály, ktoré môžu odvodiť prázdny reťazec (ε).
    """
    epsilon_nt = set()
    changed = True
    while changed:
        changed = False
        for nt, productions in grammar.items():
            if nt in epsilon_nt:
                continue
            for prod in productions:
                if prod == "":
                    epsilon_nt.add(nt)
                    changed = True
                    break
                else:
                    all_eps = True
                    for ch in prod:
                        if ch in grammar and ch not in epsilon_nt:
                            all_eps = False
                            break
                        elif ch not in grammar:
                            all_eps = False
                            break
                    if all_eps:
                        epsilon_nt.add(nt)
                        changed = True
                        break
    return epsilon_nt


def parse_production(prod):
    """Rozdelí reťazec produkcie na symboly (1 znak = 1 symbol)."""
    return list(prod)


def join_production(symbols):
    """Zloží zoznam symbolov do reťazca."""
    return "".join(symbols)


def remove_epsilon_productions(grammar, start_symbol, epsilon_nt):
    """
    Odstráni ε‑pravidlá (A->ε) a vytvorí varianty produkcií,
    kde sa epsilonotvorné neterminály vynechajú.
    """
    new_grammar = {}
    for A in grammar.keys():
        new_grammar[A] = set()
    for A, productions in grammar.items():
        for p in productions:
            symbols = parse_production(p)
            nullable_positions = [i for i, sym in enumerate(symbols) if sym in epsilon_nt]
            subsets = itertools.chain.from_iterable(
                itertools.combinations(nullable_positions, r)
                for r in range(len(nullable_positions) + 1)
            )
            for subset in subsets:
                new_symbols = list(symbols)
                for idx in sorted(subset, reverse=True):
                    new_symbols.pop(idx)
                new_p = join_production(new_symbols)
                new_grammar[A].add(new_p)
    for A in list(new_grammar.keys()):
        if "" in new_grammar[A]:
            new_grammar[A].remove("")
    final_grammar = {}
    for A, prod_set in new_grammar.items():
        if prod_set:
            final_grammar[A] = list(prod_set)
    return final_grammar


def create_new_start_symbol_if_epsilon(final_grammar, original_start, epsilon_nt):
    """
    Ak je pôvodný štartovací symbol ε‑tvorivý,
    pridá sa nový štartovací symbol S' s pravidlami:
       S' -> original_start  |  ε
    """
    if original_start in epsilon_nt and original_start in final_grammar:
        new_start = original_start + "'"
        final_grammar[new_start] = [original_start, ""]
        return final_grammar, new_start
    return final_grammar, original_start


def find_neperspektivne(grammar, non_terminals):
    """
    Zistí neperspektívne (neproduktívne) neterminály.
    """
    productive = set()
    changed = True
    while changed:
        changed = False
        for nt, productions in grammar.items():
            if nt in productive:
                continue
            for prod in productions:
                symbols = parse_production(prod)
                is_prod = True
                for sym in symbols:
                    if sym in non_terminals and sym not in productive:
                        is_prod = False
                        break
                if is_prod:
                    productive.add(nt)
                    changed = True
                    break
    return set(non_terminals) - productive


def remove_unproductive(grammar, unproductive):
    """
    Odstráni neperspektívne neterminály a pravidlá, ktoré ich obsahujú.
    """
    clean = {}
    for nt, productions in grammar.items():
        if nt in unproductive:
            continue
        valid = []
        for prod in productions:
            if any(u in prod for u in unproductive):
                continue
            valid.append(prod)
        if valid:
            clean[nt] = valid
    return clean


def find_unreachable(grammar, start_symbol, protected=set()):
    """
    Zistí neterminály, ktoré nie sú dostupné zo štartovacieho symbolu.
    Neterminály v 'protected' zostanú vždy dostupné.
    """
    if start_symbol not in grammar:
        return set(grammar.keys()) - protected
    reachable = set(protected)
    reachable.add(start_symbol)
    queue = [start_symbol]
    while queue:
        cur = queue.pop()
        if cur not in grammar:
            continue
        for prod in grammar[cur]:
            for nt in grammar.keys():
                if nt in prod and nt not in reachable:
                    reachable.add(nt)
                    queue.append(nt)
    return set(grammar.keys()) - reachable


def remove_unreachable(grammar, unreachable, protected=set()):
    """
    Odstráni nedostupné neterminály a pravidlá, ktoré ich obsahujú,
    ale neterminály v 'protected' ponechá.
    """
    clean = {}
    for nt, productions in grammar.items():
        if nt in unreachable and nt not in protected:
            continue
        valid = []
        for prod in productions:
            if any(u in prod for u in unreachable if u not in protected):
                continue
            valid.append(prod)
        if valid:
            clean[nt] = valid
    return clean


# NOVÉ FUNKCIE NA DETEKCIU ĽAVEJ REKURZIE

def check_left_recursion(grammar):
    """
    Zisťuje ľavú rekurziu v gramatike podľa definícií:
      - Priama ľavá rekurzia: A -> Aα
      - Nepriama ľavá rekurzia: A => Bα =>* Aα'
    Vráti dvojicu množín (direct, indirect).
    """
    direct = set()
    indirect = set()

    # Pre každý neterminál A a každú produkciu A->prod kontrolujeme:
    for A, productions in grammar.items():
        for prod in productions:
            if not prod:
                # Prázdna produkcia (epsilon) nás nezaujíma pri ľavej rekurzii
                continue

            # 1) Priama ľavá rekurzia (A -> Aα)
            if prod[0] == A:
                direct.add(A)

            # 2) Nepriama ľavá rekurzia:
            #    A -> Bα a z B (cez ľavé symboly) po viacerých krokoch => A
            #    T.j. zisťujeme, či B vedie k produkcii začínajúcej A
            elif prod[0].isupper() and prod[0] != A:
                B = prod[0]
                if leads_leftmost_to_A(A, B, grammar):
                    indirect.add(A)

    return direct, indirect


def leads_leftmost_to_A(current, target, grammar, visited=None):
    """
    Zistí, či z neterminálu 'current' existuje (ľavmostná) derivácia,
    ktorej prvý symbol je 'target'.

    T. j. hľadáme, či existuje nejaké pravidlo current -> targetγ
    alebo current -> Xγ s X isupper() a rekurzívne leads_leftmost_to_A(X, target, ...)
    """
    if visited is None:
        visited = set()

    # Ak sme tento neterminál už spracovali, vrátime False (vyhneme sa cyklu).
    if current in visited:
        return False
    visited.add(current)

    # Pre každú produkciu current -> p
    for p in grammar.get(current, []):
        if not p:
            continue
        first_sym = p[0]
        # Ak prvý symbol p je rovnaký ako target, našli sme odvodenie
        if first_sym == target:
            return True
        # Ak je to neterminál a nie je to target, skúmame rekurzívne
        if first_sym.isupper() and first_sym != target:
            if leads_leftmost_to_A(first_sym, target, grammar, visited.copy()):
                return True

    return False



# FUNKCIE PRE ODSTRAŇOVANIE PRIAMEJ A NEPRIAMEJ ĽAVEJ REKURZIE (IBA ODZADU)

def remove_direct_left_recursion_for(ordered_nonterminals, grammar, orig_start):
    """
    Odstráni priamu ľavú rekurziu pre zadaný zoznam neterminálov.
    Ak je neterminál rovný orig_start, vytvorí sa nový neterminál "Z",
    inak sa použije nt + "'" (pripájanie apostrofov).
    """
    for nt in ordered_nonterminals:
        if nt not in grammar:
            continue
        prods = grammar[nt]
        alpha = []
        beta = []
        for prod in prods:
            if prod.startswith(nt):
                alpha.append(prod[len(nt):])
            else:
                beta.append(prod)
        if alpha:
            if nt == orig_start and 'Z' not in ordered_nonterminals:
                candidate = "Z"
                # Pridáme nový neterminál na začiatok poradia
                ordered_nonterminals.insert(0, candidate)
            else:
                candidate = nt + "'"
            while candidate in grammar:
                candidate += "'"
            grammar[candidate] = []
            new_beta = []
            for b in beta:
                # Zachováme pôvodné beta aj ich rozšírenú verziu s candidate
                new_beta.append(b)
                new_beta.append(b + candidate)
            grammar[nt] = new_beta
            new_alpha = []
            for a in alpha:
                new_alpha.append(a + candidate)
                new_alpha.append(a)
            grammar[candidate] = new_alpha


def remove_indirect_left_recursion_bottom_up(grammar, ordered_nonterminals, orig_start, direct):
    """
    Odstráni nepriamu ľavú rekurziu pomocou substitúcie zdola nahor.
    Najprv sa vykoná odstránenie priamych rekurzií pre všetky neterminály
    a následne sa dosadia pravidlá substitúciou.
    """
    G = {A: list(prods) for A, prods in grammar.items()}
    # Najprv odstránime priamu ľavú rekurziu pre všetky neterminály podľa zvoleného poradia
    if direct:
        remove_direct_left_recursion_for(ordered_nonterminals, G, orig_start)
        direct = False
    # Potom vykonáme substitúciu, aby sme odstránili nepriamu ľavú rekurziu
    for i in reversed(range(len(ordered_nonterminals))):
        Ai = ordered_nonterminals[i]
        if Ai not in G:
            continue
        for j in range(i + 1):
            Aj = ordered_nonterminals[j]
            if Aj not in G:
                continue
            if Aj == Ai:
                continue
            new_prods = []
            for prod in G[Aj]:
                if prod.startswith(Ai):
                    alpha = prod[len(Ai):]
                    for gamma in G[Ai]:
                        new_prods.append(gamma + alpha)
                else:
                    new_prods.append(prod)
            G[Aj] = new_prods
    return G


def merge_new_with_original(grammar, original_nonterminals):
    """
    Prejde gramatiku a pre každý neterminál, ktorý NIE JE v original_nonterminals,
    ak existuje neterminál z original_nonterminals s rovnakou canonical formou,
    nahradí nový neterminál tým pôvodným.
    """
    new_grammar = dict(grammar)
    for nt in list(new_grammar.keys()):
        if nt in original_nonterminals:
            continue
        canon_nt = sorted(canonical_form(p) for p in new_grammar[nt])
        for old_nt in original_nonterminals:
            if old_nt in new_grammar:
                canon_old = sorted(canonical_form(p) for p in new_grammar[old_nt])
                if canon_nt == canon_old:
                    new_grammar = force_rename_new_to_old(new_grammar, old_nt, nt)
                    break
    return new_grammar


def merge_new_with_original_fixpoint(grammar, original_nonterminals):
    """
    Opakovane volá merge_new_with_original, kým sa nedosiahne fixpoint.
    """
    changed = True
    current = grammar
    while changed:
        new_grammar = merge_new_with_original(current, original_nonterminals)
        if new_grammar == current:
            changed = False
        else:
            current = new_grammar
            changed = True
    return current


def force_rename_new_to_old(grammar, old_nt, new_nt):
    """
    Vo všetkých produkciách nahradí výskyty new_nt za old_nt,
    zlúči produkcie (ponechá iba tie pôvodné old_nt),
    a odstráni new_nt z gramatiky.
    """
    if new_nt not in grammar or old_nt not in grammar:
        return grammar
    new_grammar = dict(grammar)
    for A in list(new_grammar.keys()):
        new_prods = []
        for p in new_grammar[A]:
            new_prods.append(p.replace(new_nt, old_nt))
        new_grammar[A] = new_prods
    if new_nt in new_grammar:
        del new_grammar[new_nt]
    return new_grammar


def generate_grammar(entry_nt, entry_t, entry_start, entry_rules, label_output):
    """
    Spracuje gramatiku a zobrazí ju po týchto krokoch:
      1) Odstránenie ε‑pravidiel.
      2) Vytvorenie nového štartovacieho neterminálu, ak je pôvodný ε‑tvorivý.
      3) Odstránenie jednoduchých pravidiel.
      4) Zistenie, či gramatika obsahuje nepriamu ľavú rekurziu.
         Ak áno, použije sa odstránenie nepriamej ľavej rekurzie zdola nahor;
         ak nie, použije sa odstránenie iba priamej ľavej rekurzie.
      5) Odstránenie neperspektívnych a nedostupných neterminálov s ochranou pre nový štart.
      6) Zlúčenie ekvivalentných neterminálov (fixpoint).
    """
    original_non_terminals = [nt.strip() for nt in entry_nt.get().split(",") if nt.strip()]
    start_symbol = entry_start.get().strip()
    rules_input = entry_rules.get("1.0", tk.END).strip().split("\n")

    # 1) Pôvodná gramatika a odstránenie ε-pravidiel
    original_grammar = process_rules(rules_input)
    epsilon_nt = find_epsilon_producing(original_grammar, original_non_terminals)
    grammar_eps = remove_epsilon_productions(original_grammar, start_symbol, epsilon_nt)

    # 2) Vytvorenie nového štartovacieho symbolu, ak je ε-tvorivý
    grammar_with_start, new_start_symbol = create_new_start_symbol_if_epsilon(grammar_eps, start_symbol, epsilon_nt)

    # 3) Odstránenie jednoduchých pravidiel
    grammar_no_simple = remove_simple_rules(grammar_with_start, find_simple_rules(grammar_with_start))

    # 4) Zistenie, či gramatika obsahuje nepriamu ľavú rekurziu
    direct = False
    direct_rec, indirect_rec = check_left_recursion(grammar_no_simple)

    if indirect_rec:
        if direct_rec:
            direct = True
        # Ak sa vyskytuje nepriamy cyklus, použijeme odstránenie nepriamej ľavej rekurzie (zdola nahor)
        ordered_nts = list(reversed(grammar_no_simple.keys()))
        """if new_start_symbol != start_symbol and new_start_symbol not in ordered_nts:
            ordered_nts.insert(0, new_start_symbol)"""
        grammar_left = remove_indirect_left_recursion_bottom_up(grammar_no_simple, ordered_nts, start_symbol, direct)

    else:
        # Inak vykonáme odstránenie iba priamej ľavej rekurzie pre každý neterminál
        ordered_nts = list(grammar_no_simple.keys())
        G = {A: list(prods) for A, prods in grammar_no_simple.items()}
        for A in ordered_nts:
            remove_direct_left_recursion_for([A], G, start_symbol)
        grammar_left = G
        direct_rec = set()
        direct = False

    grammar_no_simple = remove_simple_rules(grammar_left, find_simple_rules(grammar_left))
    direct_rec, indirect_rec = check_left_recursion(grammar_no_simple)
    if indirect_rec:
        # Ak sa vyskytuje nepriamy cyklus, použijeme odstránenie nepriamej ľavej rekurzie (zdola nahor)
        ordered_nts = list(reversed(grammar_no_simple.keys()))
        if new_start_symbol != start_symbol and new_start_symbol not in ordered_nts:
            ordered_nts.insert(0, new_start_symbol)
        grammar_left = remove_indirect_left_recursion_bottom_up(grammar_no_simple, ordered_nts, start_symbol, direct)
    else:
        # Inak vykonáme odstránenie iba priamej ľavej rekurzie pre každý neterminál
        ordered_nts = list(grammar_no_simple.keys())
        G = {A: list(prods) for A, prods in grammar_no_simple.items()}
        for A in ordered_nts:
            remove_direct_left_recursion_for([A], G, start_symbol)
        grammar_left = G
        direct_rec = set()
        direct = False

    # 5) Odstránenie neperspektívnych a nedostupných neterminálov, pričom chránime nový štart.
    protected = {new_start_symbol}

    unproductive = find_neperspektivne(grammar_left, original_non_terminals)
    grammar_prod = remove_unproductive(grammar_left, unproductive)
    unreachable = find_unreachable(grammar_prod, new_start_symbol, protected)
    grammar_reach = remove_unreachable(grammar_prod, unreachable, protected)

    # 6) Zlúčenie ekvivalentných neterminálov (fixpoint)
    final_grammar = merge_equivalent_non_terminals_fixpoint(grammar_reach, original_non_terminals)

    # Výslednú gramatiku zobrazíme
    lines = []
    if final_grammar:
        for lhs, prods in final_grammar.items():
            pstr = " | ".join("ε" if p == "" else p for p in prods)
            lines.append(f"{lhs} -> {pstr}")
        output = "\n".join(lines)
    else:
        output = "Žiadna gramatika neostala"
    label_output.config(text="Výsledná gramatika:\n" + output)


### FUNKCIE PRE GRAFICKÉ ROZHRANIE ###

def setup_main_frame():
    frame_main.grid_rowconfigure(0, weight=0)
    frame_main.grid_rowconfigure(1, weight=0)
    frame_main.grid_rowconfigure(2, weight=1)
    frame_main.grid_columnconfigure(0, weight=1)
    title_frame = tk.Frame(frame_main, bg=BG_COLOR)
    title_frame.grid(row=0, column=0, pady=(20, 10), sticky="n")
    tk.Label(title_frame, text="Testovanie ekvivalencie", font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack()
    tk.Label(title_frame, text="bezkontextových gramatík", font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack()
    frame_buttons = tk.Frame(frame_main, bg=BG_COLOR)
    frame_buttons.grid(row=1, column=0, pady=(10, 0), sticky="n")
    tk.Button(frame_buttons, text="Zadávanie gramatiky G1",
              command=lambda: show_frame(frame_grammar1),
              font=BUTTON_FONT, width=20, height=2, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)
    tk.Button(frame_buttons, text="Zadávanie gramatiky G2",
              command=lambda: show_frame(frame_grammar2),
              font=BUTTON_FONT, width=20, height=2, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)


def setup_grammar_frame(frame, title_text):
    frame.grid_rowconfigure(0, weight=0)
    frame.grid_rowconfigure(1, weight=0)
    frame.grid_rowconfigure(2, weight=0)
    frame.grid_rowconfigure(3, weight=0)
    frame.grid_rowconfigure(4, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    tk.Label(frame, text=title_text, font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(
        row=0, column=0, pady=(10, 5), sticky="n"
    )
    frame_inputs = tk.Frame(frame, bg=BG_COLOR)
    frame_inputs.grid(row=1, column=0, pady=(5, 10), sticky="n")
    labels = ["N -", "T -", "S -", "P -"]
    entries = []
    for i, lbl in enumerate(labels):
        tk.Label(frame_inputs, text=lbl, font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(
            row=i, column=0, pady=5, sticky="w"
        )
        if i < 3:
            entry = tk.Entry(frame_inputs, font=ENTRY_FONT)
        else:
            entry = tk.Text(frame_inputs, width=40, height=4, font=ENTRY_FONT)
        entry.grid(row=i, column=1, pady=5, padx=10, sticky="ew")
        entries.append(entry)
    frame_inputs.grid_columnconfigure(1, weight=1)
    label_output = tk.Label(frame, text="", font=ENTRY_FONT, bg=BG_COLOR, fg=TEXT_COLOR)
    label_output.grid(row=2, column=0, pady=10)
    frame_buttons = tk.Frame(frame, bg=BG_COLOR)
    frame_buttons.grid(row=3, column=0, pady=(10, 0), sticky="n")
    tk.Button(frame_buttons, text="Zobraziť gramatiku",
              command=lambda: generate_grammar(*entries, label_output),
              font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)
    tk.Button(frame_buttons, text="Späť",
              command=lambda: show_frame(frame_main, entries),
              font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)


### HLAVNÉ NASTAVENIA GUI ###
BG_COLOR = '#d0e7f9'
TEXT_COLOR = '#00274d'
BUTTON_BG = '#00509e'
BUTTON_FG = 'white'
TITLE_FONT = ("Arial", 20, "bold")
LABEL_FONT = ("Arial", 14)
ENTRY_FONT = ("Arial", 14)
BUTTON_FONT = ("Arial", 16)

root = tk.Tk()
root.title("Testovanie")
root.geometry("800x500")
root.configure(bg=BG_COLOR)
container = tk.Frame(root)
container.pack(fill="both", expand=True)
container.grid_rowconfigure(0, weight=1)
container.grid_columnconfigure(0, weight=1)
frame_main = tk.Frame(container, bg=BG_COLOR)
frame_grammar1 = tk.Frame(container, bg=BG_COLOR)
frame_grammar2 = tk.Frame(container, bg=BG_COLOR)
for f in (frame_main, frame_grammar1, frame_grammar2):
    f.grid(row=0, column=0, sticky="nsew")
setup_main_frame()
setup_grammar_frame(frame_grammar1, "Zadávanie gramatiky G1")
setup_grammar_frame(frame_grammar2, "Zadávanie gramatiky G2")
show_frame(frame_main)
root.mainloop()