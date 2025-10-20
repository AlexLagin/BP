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
                    merged_grammar[A] = [p.replace(nt, winner) for p in merged_grammar[A]]
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
    new_grammar = {A: set() for A in grammar}
    for A, productions in grammar.items():
        for p in productions:
            symbols = parse_production(p)
            nullable_positions = [i for i, sym in enumerate(symbols) if sym in epsilon_nt]
            subsets = itertools.chain.from_iterable(
                itertools.combinations(nullable_positions, r)
                for r in range(len(nullable_positions) + 1)
            )
            for subset in subsets:
                new_symbols = [s for i, s in enumerate(symbols) if i not in subset]
                new_grammar[A].add(join_production(new_symbols))
    for A in new_grammar:
        new_grammar[A].discard("")
    final_grammar = {A: list(prods) for A, prods in new_grammar.items() if prods}
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
                if all((ch not in grammar) or (ch in productive) for ch in prod):
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
        valid = [p for p in productions if not any(u in p for u in unproductive)]
        if valid:
            clean[nt] = valid
    return clean

def find_unreachable(grammar, start_symbol, protected=set()):
    """
    Zistí neterminály, ktoré nie sú dostupné zo štartovacieho symbolu.
    Neterminály v 'protected' zostanú vždy dostupné.
    """
    if start_symbol not in grammar:
        return set(grammar) - protected
    reachable = set(protected) | {start_symbol}
    queue = [start_symbol]
    while queue:
        cur = queue.pop()
        for prod in grammar.get(cur, []):
            for nt in grammar:
                if nt in prod and nt not in reachable:
                    reachable.add(nt)
                    queue.append(nt)
    return set(grammar) - reachable

def remove_unreachable(grammar, unreachable, protected=set()):
    """
    Odstráni nedostupné neterminály a pravidlá, ktoré ich obsahujú,
    ale neterminály v 'protected' ponechá.
    """
    clean = {}
    for nt, productions in grammar.items():
        if nt in unreachable and nt not in protected:
            continue
        valid = [p for p in productions if not any(u in p for u in unreachable if u not in protected)]
        if valid:
            clean[nt] = valid
    return clean

def check_left_recursion(grammar):
    """
    Zisťuje ľavú rekurziu v gramatike podľa definícií:
      - Priama ľavá rekurzia: A -> Aα
      - Nepriama ľavá rekurzia: A => Bα =>* Aα'
    Vráti dvojicu množín (direct, indirect).
    """
    direct, indirect = set(), set()
    for A, prods in grammar.items():
        for p in prods:
            if p and p[0] == A:
                direct.add(A)
            elif p and p[0].isupper() and p[0] != A:
                if leads_leftmost_to_A(A, p[0], grammar):
                    indirect.add(A)
    return direct, indirect

def leads_leftmost_to_A(current, target, grammar, visited=None):
    """
    Pomocná funkcia pre detekciu nepriamych cyklov ľavej rekurzie.
    """
    if visited is None:
        visited = set()
    if current in visited:
        return False
    visited.add(current)
    for p in grammar.get(current, []):
        if p and p[0] == target:
            return True
        if p and p[0].isupper() and p[0] != target:
            if leads_leftmost_to_A(p[0], target, grammar, visited.copy()):
                return True
    return False

def remove_direct_left_recursion_for(ordered_nonterminals, grammar, orig_start):
    """
    Odstráni priamu ľavú rekurziu pre každý neterminál A v ordered_nonterminals.
    """
    for nt in ordered_nonterminals:
        if nt not in grammar:
            continue
        prods = grammar[nt]
        alpha, beta = [], []
        for prod in prods:
            if prod.startswith(nt):
                alpha.append(prod[len(nt):])
            else:
                beta.append(prod)
        if alpha:
            candidate = "Z" if nt == orig_start else nt + "'"
            while candidate in grammar:
                candidate += "'"
            grammar[candidate] = []
            new_beta = []
            for b in beta:
                new_beta += [b, b + candidate]
            grammar[nt] = new_beta
            new_alpha = []
            for a in alpha:
                new_alpha += [a + candidate, a]
            grammar[candidate] = new_alpha

def remove_indirect_left_recursion_bottom_up(grammar, ordered_nonterminals, orig_start):
    """
    Odstráni nepriame ľavé rekurzie:
    najprv priamu, potom postupne mení Aj->Aiα, ...
    """
    G = {A: list(prods) for A, prods in grammar.items()}
    remove_direct_left_recursion_for(ordered_nonterminals, G, orig_start)
    for i in reversed(range(len(ordered_nonterminals))):
        Ai = ordered_nonterminals[i]
        if Ai not in G:
            continue
        for j in range(i):
            Aj = ordered_nonterminals[j]
            if Aj not in G:
                continue
            new_prods = []
            for prod in G[Aj]:
                if prod.startswith(Ai):
                    suff = prod[len(Ai):]
                    for g in G[Ai]:
                        new_prods.append(g + suff)
                else:
                    new_prods.append(prod)
            G[Aj] = new_prods
    return G

def merge_new_with_original(grammar, original_nonterminals):
    """
    Zlúči novovzniknuté neterminály s pôvodnými.
    """
    new_grammar = dict(grammar)
    for nt in list(new_grammar):
        if nt in original_nonterminals:
            continue
        canon_nt = sorted(canonical_form(p) for p in new_grammar[nt])
        for old in original_nonterminals:
            if old in new_grammar:
                canon_old = sorted(canonical_form(p) for p in new_grammar[old])
                if canon_nt == canon_old:
                    new_grammar = force_rename_new_to_old(new_grammar, old, nt)
                    break
    return new_grammar

def merge_new_with_original_fixpoint(grammar, original_nonterminals):
    """
    Fixpoint pre merge_new_with_original.
    """
    changed = True
    current = grammar
    while changed:
        new_grammar = merge_new_with_original(current, original_nonterminals)
        changed = (new_grammar != current)
        current = new_grammar
    return current

def force_rename_new_to_old(grammar, old_nt, new_nt):
    """
    Premenuje všetky výskyty new_nt na old_nt a odstráni new_nt.
    """
    if new_nt not in grammar or old_nt not in grammar:
        return grammar
    updated = {}
    for A, prods in grammar.items():
        updated[A] = [p.replace(new_nt, old_nt) for p in prods]
    updated.pop(new_nt, None)
    return updated

def generate_grammar(entry_start, entry_rules, label_output):
    """
    Spracuje vstupnú gramatiku krok za krokom:
    ε-pravidlá, nový start, jednoduché, ľavá rekurzia,
    neperspektívne, nedostupné, zlúčenie NT.
    """
    S = entry_start.get().strip()
    rules_in = entry_rules.get("1.0", tk.END).strip().splitlines()
    G0 = process_rules(rules_in)
    orig_nt = list(G0)

    eps = find_epsilon_producing(G0, orig_nt)
    G1 = remove_epsilon_productions(G0, S, eps)
    G2, S2 = create_new_start_symbol_if_epsilon(G1, S, eps)

    G3 = remove_simple_rules(G2, find_simple_rules(G2))
    direct, indirect = check_left_recursion(G3)
    if indirect:
        order = list(orig_nt)
        if S2 not in order:
            order.insert(0, S2)
        G4 = remove_indirect_left_recursion_bottom_up(G3, order, S)
    else:
        G4 = dict(G3)
        for A in list(G3):
            remove_direct_left_recursion_for([A], G4, S)

    unprod = find_neperspektivne(G4, orig_nt)
    G5 = remove_unproductive(G4, unprod)
    unreach = find_unreachable(G5, S2, {S2, "Z"})
    G6 = remove_unreachable(G5, unreach, {S2, "Z"})

    G7 = merge_equivalent_non_terminals_fixpoint(G6, orig_nt)

    lines = [f"{A} -> " + " | ".join("ε" if p=="" else p for p in prods)
             for A, prods in G7.items()]
    label_output.config(text="Výsledná gramatika:\n" + "\n".join(lines))


### FUNKCIE PRE GRAFICKÉ ROZHRANIE ###

BG_COLOR    = '#d0e7f9'
TEXT_COLOR  = '#00274d'
BUTTON_BG   = '#00509e'
BUTTON_FG   = 'white'
TITLE_FONT  = ("Arial", 20, "bold")
LABEL_FONT  = ("Arial", 14)
ENTRY_FONT  = ("Arial", 14)
BUTTON_FONT = ("Arial", 16)

root = tk.Tk()
root.title("Testovanie ekvivalencie bezkontextových gramatík")
root.geometry("1000x700")   # Väčšie hlavné okno
root.configure(bg=BG_COLOR)

container = tk.Frame(root)
container.pack(fill="both", expand=True)
container.grid_rowconfigure(0, weight=1)
container.grid_columnconfigure(0, weight=1)

frame_main     = tk.Frame(container, bg=BG_COLOR)
frame_grammar1 = tk.Frame(container, bg=BG_COLOR)
frame_grammar2 = tk.Frame(container, bg=BG_COLOR)
for f in (frame_main, frame_grammar1, frame_grammar2):
    f.grid(row=0, column=0, sticky="nsew")

def setup_main_frame():
    frame_main.grid_rowconfigure(0, weight=0)
    frame_main.grid_rowconfigure(1, weight=1)
    frame_main.grid_columnconfigure(0, weight=1)
    tk.Label(frame_main,
             text="Testovanie ekvivalencie bezkontextových gramatík",
             font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=(20,10))
    btnf = tk.Frame(frame_main, bg=BG_COLOR)
    # Menšia medzera nad tlačidlami, tlačidlá vyššie
    btnf.pack(pady=(0,20), expand=True)
    tk.Button(btnf, text="Zadávanie gramatiky G1",
              command=lambda: show_frame(frame_grammar1),
              font=BUTTON_FONT, width=20, height=2,
              bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)
    tk.Button(btnf, text="Zadávanie gramatiky G2",
              command=lambda: show_frame(frame_grammar2),
              font=BUTTON_FONT, width=20, height=2,
              bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)

def setup_grammar_frame(frame, title_text):
    # Definícia rozvrhnutia riadkov a stĺpcov
    for i in range(7):
        frame.grid_rowconfigure(i, weight=0)
    frame.grid_rowconfigure(5, weight=1)   # expanzia až pod výstupom
    frame.grid_columnconfigure(0, weight=1)

    # Nadpis sekcie
    tk.Label(frame, text=title_text,
             font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(row=0, column=0, pady=(10,5))

    # Štartovací neterminál – label nad vstupom, centrovaný
    tk.Label(frame, text="Štartovací neterminál",
             font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(row=1, column=0, pady=5)
    entry_start = tk.Entry(frame, font=ENTRY_FONT)
    entry_start.grid(row=2, column=0, sticky="ew", padx=(200,200), pady=5)

    # Pravidlá – label nad textom, centrovaný
    tk.Label(frame, text="Pravidlá",
             font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).grid(row=3, column=0, pady=5)
    entry_rules = tk.Text(frame, width=60, height=8, font=ENTRY_FONT)
    entry_rules.grid(row=4, column=0, sticky="ew", padx=(200,200), pady=5)

    # Výstup – centrovaný
    label_output = tk.Label(frame, text="", font=ENTRY_FONT,
                            bg=BG_COLOR, fg=TEXT_COLOR, justify="center")
    label_output.grid(row=5, column=0, sticky="ew", padx=20, pady=10)

    # Tlačidlá
    btnf = tk.Frame(frame, bg=BG_COLOR)
    btnf.grid(row=6, column=0, pady=(10,0))
    tk.Button(btnf, text="Zobraziť gramatiku",
              command=lambda: generate_grammar(entry_start, entry_rules, label_output),
              font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)
    tk.Button(btnf, text="Späť",
              command=lambda: show_frame(frame_main, [entry_start, entry_rules]),
              font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG).pack(pady=5)

# Inicializácia rámov
setup_main_frame()
setup_grammar_frame(frame_grammar1, "Zadávanie gramatiky G1")
setup_grammar_frame(frame_grammar2, "Zadávanie gramatiky G2")
show_frame(frame_main)

root.mainloop()
