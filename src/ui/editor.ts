
import { EditorState, Compartment } from "@codemirror/state";
import {
  EditorView,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  drawSelection,
  highlightSpecialChars,
} from "@codemirror/view";
import { defaultKeymap } from "@codemirror/commands";
import {
  search,
  searchKeymap,
  openSearchPanel,
  highlightSelectionMatches,
} from "@codemirror/search";
import {
  syntaxHighlighting,
  HighlightStyle,
  bracketMatching,
  foldGutter,
  codeFolding,
} from "@codemirror/language";
import { java } from "@codemirror/lang-java";
import { tags as t } from "@lezer/highlight";

const theme = EditorView.theme(
  {
    "&": {
      color: "#e6e7ea",
      backgroundColor: "#0c0d10",
      height: "100%",
      fontSize: "12.5px",
    },
    ".cm-scroller": {
      fontFamily:
        '"JetBrains Mono","IBM Plex Mono","SF Mono","Cascadia Code",Consolas,monospace',
      lineHeight: "1.5",
    },
    ".cm-content": { caretColor: "#e8a13a" },
    ".cm-gutters": {
      backgroundColor: "#0c0d10",
      color: "#5a5d66",
      border: "none",
      borderRight: "1px solid #1a1b21",
    },
    ".cm-activeLineGutter": { backgroundColor: "#15161b", color: "#8b8e98" },
    ".cm-activeLine": { backgroundColor: "rgba(29,31,38,0.5)" },
    ".cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection": {
      backgroundColor: "#2c2f3a !important",
    },
    ".cm-cursor": { borderLeftColor: "#e8a13a" },
    ".cm-foldGutter span": { color: "#5a5d66" },
    ".cm-panels": { backgroundColor: "#15161b", color: "#e6e7ea" },
    ".cm-panels.cm-panels-bottom": { borderTop: "1px solid #2a2c34" },
    ".cm-searchMatch": { backgroundColor: "#4a3a1a", outline: "1px solid #8a6526" },
    ".cm-searchMatch-selected": { backgroundColor: "#e8a13a", color: "#0c0d10" },
    ".cm-textfield": {
      backgroundColor: "#0c0d10",
      border: "1px solid #2a2c34",
      color: "#e6e7ea",
      fontFamily: "monospace",
    },
    ".cm-button": {
      backgroundColor: "#1d1f26",
      border: "1px solid #2a2c34",
      color: "#e6e7ea",
      backgroundImage: "none",
    },
    ".cm-line": { padding: "0 6px" },
    "&.cm-focused": { outline: "none" },
  },
  { dark: true }
);

const highlight = HighlightStyle.define([
  { tag: t.keyword, color: "#e8a13a" },
  { tag: [t.controlKeyword, t.moduleKeyword], color: "#e8a13a" },
  { tag: [t.name, t.deleted, t.character, t.propertyName], color: "#e6e7ea" },
  { tag: [t.function(t.variableName), t.labelName], color: "#7fb0d9" },
  { tag: [t.definition(t.name), t.separator], color: "#e6e7ea" },
  { tag: [t.typeName, t.className, t.namespace], color: "#5ec9b0" },
  { tag: [t.number, t.bool, t.null], color: "#d99a5e" },
  { tag: [t.string, t.special(t.string)], color: "#9ccf8f" },
  { tag: [t.comment, t.lineComment, t.blockComment], color: "#5a5d66", fontStyle: "italic" },
  { tag: [t.operator, t.operatorKeyword], color: "#8b8e98" },
  { tag: [t.meta, t.annotation], color: "#b08fd9" },
  { tag: t.invalid, color: "#d65b5b" },
  { tag: [t.bracket, t.squareBracket, t.paren], color: "#8b8e98" },
]);

export class CodeViewer {
  private view: EditorView;
  private lang = new Compartment();

  constructor(parent: HTMLElement) {
    this.view = new EditorView({
      parent,
      state: this.makeState("", "java"),
    });
  }

  private makeState(doc: string, language: "java" | "bytecode"): EditorState {
    const langExt = language === "java" ? [this.lang.of(java())] : [this.lang.of([])];
    return EditorState.create({
      doc,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        highlightSpecialChars(),
        drawSelection(),
        codeFolding(),
        foldGutter(),
        bracketMatching(),
        highlightSelectionMatches(),
        search({ top: true }),
        syntaxHighlighting(highlight),
        theme,
        EditorState.readOnly.of(true),
        EditorView.editable.of(false),
        EditorView.lineWrapping,
        keymap.of([...searchKeymap, ...defaultKeymap]),
        ...langExt,
      ],
    });
  }

  setDoc(code: string, language: "java" | "bytecode") {
    this.view.setState(this.makeState(code, language));
  }

  jumpToLine(line: number) {
    if (line < 1) return;
    const doc = this.view.state.doc;
    const n = Math.min(line, doc.lines);
    const l = doc.line(n);
    this.view.dispatch({
      selection: { anchor: l.from, head: l.to },
      effects: EditorView.scrollIntoView(l.from, { y: "center" }),
    });
    this.view.focus();
  }

  openSearch() {
    this.view.focus();
    openSearchPanel(this.view);
  }

  focus() {
    this.view.focus();
  }
}
